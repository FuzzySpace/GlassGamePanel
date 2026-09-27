package alloc

import (
	"strings"
	"sync"
	"testing"
)

func TestTorN5ULAPool(t *testing.T) {
	p, err := New(PoolTorN5ULA)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "tor-n5-ula-test" || p.NodeID() != "5" || p.Prefix() != "fdba:17c8:6c94::/64" {
		t.Fatalf("identity name=%s node=%s prefix=%s", p.Name(), p.NodeID(), p.Prefix())
	}
	if p.Free() != 32 {
		t.Fatalf("free %d", p.Free())
	}
	if _, err := New("chi-managed-inventory"); err == nil {
		t.Fatal("unknown pool accepted")
	}

	seen := map[int]struct{}{}
	for i := 0; i < 32; i++ {
		pair, ok := p.Claim()
		if !ok {
			t.Fatalf("claim %d failed", i)
		}
		if pair.IPv4.Family != "ipv4" || pair.IPv6.Family != "ipv6" {
			t.Fatalf("family %#v %#v", pair.IPv4, pair.IPv6)
		}
		if pair.IPv4.IP != PublicIPv4 || pair.IPv4.Port != 25600+i || !pair.IPv4.Routable {
			t.Fatalf("ipv4 %#v", pair.IPv4)
		}
		if i == 0 && pair.IPv6.IP != "fdba:17c8:6c94::2000" {
			t.Fatalf("first ula %s", pair.IPv6.IP)
		}
		if i == 16 && pair.IPv6.IP != "fdba:17c8:6c94::2010" {
			t.Fatalf("mid ula %s", pair.IPv6.IP)
		}
		if i == 31 && pair.IPv6.IP != "fdba:17c8:6c94::201f" {
			t.Fatalf("last ula %s", pair.IPv6.IP)
		}
		if pair.IPv6.Routable || !strings.Contains(pair.IPv6.Notes, "not public AAAA") || !strings.HasPrefix(pair.IPv6.IP, "fdba:17c8:6c94::") {
			t.Fatalf("ipv6 %#v", pair.IPv6)
		}
		if pair.IPv4.Port != pair.IPv6.Port || pair.IPv4.NodeID != "5" || pair.IPv6.Pool != PoolTorN5ULA {
			t.Fatalf("pair mismatch %#v %#v", pair.IPv4, pair.IPv6)
		}
		if pair.IPv4.IP == "45.45.239.7" || pair.IPv6.IP == "45.45.239.7" || pair.IPv4.IP == "10.99.0.34" {
			t.Fatalf("claimed a forbidden address %#v", pair)
		}
		if _, dup := seen[pair.IPv4.Port]; dup {
			t.Fatalf("duplicate port %d", pair.IPv4.Port)
		}
		seen[pair.IPv4.Port] = struct{}{}
	}
	if p.Free() != 0 {
		t.Fatalf("free after drain %d", p.Free())
	}
	if _, ok := p.Claim(); ok {
		t.Fatal("claim past drain")
	}
}

func TestClaimConcurrent(t *testing.T) {
	p, err := New(PoolTorN5ULA)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ports := make(chan int, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, ok := p.Claim()
			if !ok {
				t.Error("claim failed")
				return
			}
			ports <- pair.IPv4.Port
		}()
	}
	wg.Wait()
	close(ports)
	seen := map[int]struct{}{}
	for port := range ports {
		if _, ok := seen[port]; ok {
			t.Fatalf("duplicate %d", port)
		}
		seen[port] = struct{}{}
	}
	if len(seen) != 32 || p.Free() != 0 {
		t.Fatalf("seen %d free %d", len(seen), p.Free())
	}
}
