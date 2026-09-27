package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Higangssh/homebutler/internal/util"
)

type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Status   string `json:"status"`
}

// Scan discovers devices on the local network.
// It determines the local subnet, pings all addresses, then reads the ARP table.
func Scan() ([]Device, error) {
	return ScanContext(context.Background())
}

// ScanContext discovers devices on the local network with cancellation support.
func ScanContext(ctx context.Context) ([]Device, error) {
	subnet, err := getLocalSubnet()
	if err != nil {
		return nil, fmt.Errorf("failed to determine local subnet: %w", err)
	}

	// Ping sweep to populate ARP table
	pingSweep(ctx, subnet)

	// Check if cancelled during sweep
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Read ARP table
	devices, err := readARP()
	if err != nil {
		return nil, fmt.Errorf("failed to read ARP table: %w", err)
	}

	resolveHostnames(ctx, devices)

	return devices, nil
}

// ptrTimeout bounds a single reverse lookup so an unreachable resolver cannot
// stall the scan.
const ptrTimeout = time.Second

// resolveHostnames fills in Device.Hostname for each device via reverse DNS.
// Lookups run concurrently because a scan typically covers dozens of addresses
// and each one may have to wait out a resolver timeout.
func resolveHostnames(ctx context.Context, devices []Device) {
	gateway := gatewayResolver()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for i := range devices {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d *Device) {
			defer wg.Done()
			defer func() { <-sem }()
			d.Hostname = lookupPTR(ctx, d.IP, gateway)
		}(&devices[i])
	}

	wg.Wait()
}

// lookupPTR returns the first PTR name for ip, or "" if nothing resolves.
func lookupPTR(ctx context.Context, ip string, gateway *net.Resolver) string {
	resolvers := []*net.Resolver{net.DefaultResolver}
	if gateway != nil && isPrivateIP(ip) {
		// Ask the LAN resolver first. Public resolvers hold no delegation for the
		// RFC1918 reverse zones, so they answer NXDOMAIN for every local address,
		// and sending those queries upstream leaks the internal address plan.
		resolvers = []*net.Resolver{gateway, net.DefaultResolver}
	}

	for _, r := range resolvers {
		if name := firstPTRName(ctx, r, ip); name != "" {
			return name
		}
	}
	return ""
}

func firstPTRName(ctx context.Context, r *net.Resolver, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, ptrTimeout)
	defer cancel()

	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsPrivate()
}

// gatewayResolver returns a resolver bound to the default gateway, which on most
// home networks is also the authoritative DNS server for the LAN zone.
// It returns nil when no default gateway can be determined.
func gatewayResolver() *net.Resolver {
	gw := defaultGateway()
	if gw == "" {
		return nil
	}

	addr := net.JoinHostPort(gw, "53")
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// defaultGateway returns the IPv4 default gateway, or "" if there is none.
// Only Linux is supported; elsewhere the route table is unreadable and callers
// fall back to the system resolver alone.
func defaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseDefaultGateway(string(data))
}

// parseDefaultGateway extracts the gateway of the first default route (a
// destination of 00000000) from /proc/net/route contents.
func parseDefaultGateway(routes string) string {
	lines := strings.Split(routes, "\n")
	for _, line := range lines[1:] { // first line is the column header
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		// Addresses are little-endian hex words: "051F10AC" is 172.16.31.5.
		v, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
	}
	return ""
}

func getLocalSubnet() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.To4()
				mask := ipnet.Mask
				// Calculate network address
				network := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					network[i] = ip[i] & mask[i]
				}
				ones, _ := mask.Size()
				return fmt.Sprintf("%s/%d", network.String(), ones), nil
			}
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

func pingSweep(ctx context.Context, subnet string) {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // limit concurrency

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		if ctx.Err() != nil {
			break
		}
		target := ip.String()
		wg.Add(1)
		select {
		case sem <- struct{}{}:
			// acquired semaphore, proceed
		case <-ctx.Done():
			wg.Done()
			wg.Wait()
			return
		}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			pingHost(t)
		}(target)
	}

	wg.Wait()
}

func pingHost(ip string) {
	switch runtime.GOOS {
	case "darwin":
		util.RunCmd("ping", "-c", "1", "-W", "500", ip)
	case "linux":
		util.RunCmd("ping", "-c", "1", "-W", "1", ip)
	case "windows":
		util.RunCmd("ping", "-n", "1", "-w", "500", ip)
	}
}

func readARP() ([]Device, error) {
	var out string
	var err error

	switch runtime.GOOS {
	case "darwin":
		out, err = util.RunCmd("/usr/sbin/arp", "-an")
	case "linux":
		out, err = util.RunCmd("arp", "-an")
	case "windows":
		out, err = util.RunCmd("arp", "-a")
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if err != nil {
		return nil, err
	}

	var devices []Device
	seen := make(map[string]bool)

	for _, line := range strings.Split(out, "\n") {
		ip, mac := parseARPLine(line)
		if ip == "" || mac == "" || mac == "(incomplete)" || mac == "<incomplete>" || strings.Contains(mac, "incomplete") || mac == "ff:ff:ff:ff:ff:ff" ||
			strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || strings.HasPrefix(ip, "255.") {
			// Filter out multicast (224.x, 239.x) and broadcast addresses
			continue
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true

		devices = append(devices, Device{
			IP:     ip,
			MAC:    mac,
			Status: "up",
		})
	}

	return devices, nil
}

func parseARPLine(line string) (string, string) {
	// macOS/Linux: ? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
	// Windows:     192.168.0.1       aa-bb-cc-dd-ee-ff     dynamic
	line = strings.TrimSpace(line)

	if strings.Contains(line, ") at ") {
		// Unix format
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			ip := strings.Trim(parts[1], "()")
			mac := parts[3]
			return ip, mac
		}
	} else {
		// Windows format
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			mac := strings.ReplaceAll(parts[1], "-", ":")
			if net.ParseIP(ip) != nil {
				return ip, mac
			}
		}
	}
	return "", ""
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ScanWithTimeout runs scan with a timeout.
// Goroutines are cancelled when the timeout expires (no leak).
func ScanWithTimeout(timeout time.Duration) ([]Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	devices, err := ScanContext(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("network scan timed out after %s", timeout)
	}
	return devices, err
}
