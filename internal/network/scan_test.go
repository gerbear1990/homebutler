package network

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestParseARPLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantIP  string
		wantMAC string
	}{
		{
			"macos-format",
			"? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]",
			"192.168.0.1",
			"aa:bb:cc:dd:ee:ff",
		},
		{
			"incomplete",
			"? (192.168.0.5) at (incomplete) on en0 ifscope [ethernet]",
			"192.168.0.5",
			"(incomplete)",
		},
		{
			"empty-line",
			"",
			"",
			"",
		},
		{
			"header-line",
			"Address    HWtype  HWaddress           Flags Mask  Iface",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, mac := parseARPLine(tt.line)
			if ip != tt.wantIP {
				t.Errorf("IP = %q, want %q", ip, tt.wantIP)
			}
			if mac != tt.wantMAC {
				t.Errorf("MAC = %q, want %q", mac, tt.wantMAC)
			}
		})
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.IP{192, 168, 1, 0}
	incrementIP(ip)
	if ip.String() != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip.String())
	}

	ip = net.IP{192, 168, 1, 255}
	incrementIP(ip)
	if ip.String() != "192.168.2.0" {
		t.Errorf("expected 192.168.2.0, got %s", ip.String())
	}
}

func TestGetLocalSubnet(t *testing.T) {
	subnet, err := getLocalSubnet()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = net.ParseCIDR(subnet)
	if err != nil {
		t.Errorf("invalid CIDR: %s", subnet)
	}
}

func TestParseARPLineWindows(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantIP  string
		wantMAC string
	}{
		{
			"windows-format",
			"  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic",
			"192.168.1.1",
			"aa:bb:cc:dd:ee:ff",
		},
		{
			"windows-static",
			"  10.0.0.1     11-22-33-44-55-66     static",
			"10.0.0.1",
			"11:22:33:44:55:66",
		},
		{
			"linux-format",
			"? (10.0.0.1) at 11:22:33:44:55:66 [ether] on eth0",
			"10.0.0.1",
			"11:22:33:44:55:66",
		},
		{
			"whitespace",
			"   ",
			"",
			"",
		},
		{
			"single-field",
			"onlyoneword",
			"",
			"",
		},
		{
			"non-ip-windows",
			"notanip  aa-bb-cc-dd-ee-ff  dynamic",
			"",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, mac := parseARPLine(tt.line)
			if ip != tt.wantIP {
				t.Errorf("IP = %q, want %q", ip, tt.wantIP)
			}
			if mac != tt.wantMAC {
				t.Errorf("MAC = %q, want %q", mac, tt.wantMAC)
			}
		})
	}
}

func TestIncrementIPEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  net.IP
		expect string
	}{
		{"normal", net.IP{10, 0, 0, 1}, "10.0.0.2"},
		{"last-octet-overflow", net.IP{10, 0, 0, 255}, "10.0.1.0"},
		{"double-overflow", net.IP{10, 0, 255, 255}, "10.1.0.0"},
		{"triple-overflow", net.IP{10, 255, 255, 255}, "11.0.0.0"},
		{"zero", net.IP{0, 0, 0, 0}, "0.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := make(net.IP, len(tt.input))
			copy(ip, tt.input)
			incrementIP(ip)
			if ip.String() != tt.expect {
				t.Errorf("incrementIP(%v) = %s, want %s", tt.input, ip.String(), tt.expect)
			}
		})
	}
}

func TestPingSweepCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should return quickly without panic
	pingSweep(ctx, "192.168.1.0/24")
}

func TestPingSweepInvalidCIDR(t *testing.T) {
	// Should return without panic for invalid CIDR
	pingSweep(context.Background(), "not-a-cidr")
}

func TestScanContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ScanContext(ctx)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestScanWithTimeoutShort(t *testing.T) {
	// 1ms timeout - should timeout before completing scan
	_, err := ScanWithTimeout(1 * time.Millisecond)
	// May or may not error depending on speed, but should not panic
	_ = err
}

func TestReadARP(t *testing.T) {
	// readARP uses real arp command - should work on macOS/Linux
	devices, err := readARP()
	if err != nil {
		t.Skipf("readARP() not available on this platform: %v", err)
	}
	// Verify returned devices have required fields
	for _, d := range devices {
		if d.IP == "" {
			t.Error("device IP should not be empty")
		}
		if d.MAC == "" {
			t.Error("device MAC should not be empty")
		}
		if d.Status != "up" {
			t.Errorf("device Status = %q, want %q", d.Status, "up")
		}
	}
}

func TestDeviceJSON(t *testing.T) {
	d := Device{
		IP:       "192.168.1.1",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "router.local",
		Status:   "up",
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var parsed Device
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if parsed != d {
		t.Errorf("JSON roundtrip mismatch: got %+v, want %+v", parsed, d)
	}
}

func TestScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network scan in short mode")
	}
	// Scan uses real network - just verify it doesn't panic
	devices, err := Scan()
	if err != nil {
		t.Skipf("Scan() failed (may lack network): %v", err)
	}
	for _, d := range devices {
		if d.IP == "" {
			t.Error("device IP should not be empty")
		}
		if d.Status != "up" {
			t.Errorf("device Status = %q, want %q", d.Status, "up")
		}
	}
	_ = devices
}

// Checked against the parser with the little-endian word reversed: reading
// "0100000A" big-endian yields 1.0.0.10, which fails this.
func TestParseDefaultGateway(t *testing.T) {
	const routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	if gw := parseDefaultGateway(routes); gw != "10.0.0.1" {
		t.Errorf("gateway = %q, want 10.0.0.1", gw)
	}
}

// A host with no default route must yield "" rather than a bogus 0.0.0.0, which
// gatewayResolver would otherwise dial as a DNS server on every scan.
func TestParseDefaultGatewayNoDefaultRoute(t *testing.T) {
	const onLinkOnly = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"

	if gw := parseDefaultGateway(onLinkOnly); gw != "" {
		t.Errorf("gateway = %q, want empty", gw)
	}

	// A default route can itself be on-link (gateway 00000000), as a point-to-point
	// tunnel installs it. There is no address to query in that case.
	const onLinkDefault = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n"

	if gw := parseDefaultGateway(onLinkDefault); gw != "" {
		t.Errorf("gateway = %q, want empty for an on-link default route", gw)
	}

	if gw := parseDefaultGateway(""); gw != "" {
		t.Errorf("gateway = %q, want empty for empty input", gw)
	}
}

// The private check is what decides whether the gateway is asked at all, so a
// public address slipping through would send LAN queries to a resolver that
// cannot answer them.
func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "172.16.0.2", "192.168.0.1"} {
		if !isPrivateIP(ip) {
			t.Errorf("%s: want private", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "not-an-ip", ""} {
		if isPrivateIP(ip) {
			t.Errorf("%q: want not private", ip)
		}
	}
}
