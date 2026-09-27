// Package alloc is the Phase A TEST allocation-pool source of truth.
//
// The only pool is tor-n5-ula-test on Ptero node 5 (prd-tor1-games-bm-01).
// It mirrors the panel rows already seeded for that node: 32 free pairs of
// public IPv4 38.135.179.34 ports 25600–25631 with ULA
// fdba:17c8:6c94::2000–::201f. That prefix is the Wings/docker
// pterodactyl_nw block fdba:17c8:6c94::/64 (fd00::/8). It is non-routable
// and is not a public AAAA.
//
// managed-inventory CHI 45.45.239.7 is not in this pool. Claiming does not dial
// Wings or the panel database (no credentials live in this process).
package alloc

import (
	"fmt"
	"sync"
)

const (
	// PoolTorN5ULA is the named SoT pool for node 5 TEST dual-stack create.
	PoolTorN5ULA = "tor-n5-ula-test"
	// NodeTorN5 is prd-tor1-games-bm-01 (9950X), panel nodes.id=5.
	NodeTorN5 = "5"
	// PrefixTorN5ULA is the non-routable IPv6 prefix already configured on
	// pterodactyl_nw / Wings. It is not a public AAAA.
	PrefixTorN5ULA = "fdba:17c8:6c94::/64"
	// PublicIPv4 is the node 5 public address paired with the ULA rows.
	// It is not the managed-inventory CHI address.
	PublicIPv4 = "38.135.179.34"

	pairCount   = 32
	portBase    = 25600
	ulaHostBase = 0x2000

	ulaNotes = "TEST ULA non-routable PhaseA dual-stack 2026-09-27; not public AAAA"
	v4Notes  = "node 5 public IPv4 paired with tor-n5-ula-test; not a managed-inventory allocation"
)

// Record is one address-family row inside a dual-stack claim.
type Record struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Family   string `json:"family"`
	Notes    string `json:"notes"`
	IPAlias  string `json:"ip_alias"`
	Routable bool   `json:"routable"`
	NodeID   string `json:"node_id"`
	Pool     string `json:"alloc_pool"`
}

// Pair is the IPv4 row and the IPv6 ULA row claimed together.
type Pair struct {
	IPv4 Record
	IPv6 Record
}

// Pool is an in-process mirror of the seeded free pairs.
type Pool struct {
	mu     sync.Mutex
	name   string
	nodeID string
	prefix string
	free   []Pair
}

// New returns the embedded pool. Only PoolTorN5ULA exists.
func New(name string) (*Pool, error) {
	if name != PoolTorN5ULA {
		return nil, fmt.Errorf("unknown allocation pool %q", name)
	}
	free := make([]Pair, pairCount)
	for i := 0; i < pairCount; i++ {
		port := portBase + i
		alias := fmt.Sprintf("ula-test-n5-%d", port)
		v6 := fmt.Sprintf("fdba:17c8:6c94::%x", ulaHostBase+i)
		free[i] = Pair{
			IPv4: Record{
				IP:       PublicIPv4,
				Port:     port,
				Family:   "ipv4",
				Notes:    v4Notes,
				IPAlias:  alias,
				Routable: true,
				NodeID:   NodeTorN5,
				Pool:     PoolTorN5ULA,
			},
			IPv6: Record{
				IP:       v6,
				Port:     port,
				Family:   "ipv6",
				Notes:    ulaNotes,
				IPAlias:  alias,
				Routable: false,
				NodeID:   NodeTorN5,
				Pool:     PoolTorN5ULA,
			},
		}
	}
	return &Pool{
		name:   PoolTorN5ULA,
		nodeID: NodeTorN5,
		prefix: PrefixTorN5ULA,
		free:   free,
	}, nil
}

// Name is the pool SoT name.
func (p *Pool) Name() string { return p.name }

// NodeID is the panel node the pairs belong to.
func (p *Pool) NodeID() string { return p.nodeID }

// Prefix is the ULA prefix. It is non-routable and not a public AAAA.
func (p *Pool) Prefix() string { return p.prefix }

// Free is the number of unclaimed IPv4+IPv6 pairs.
func (p *Pool) Free() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.free)
}

// Claim takes the next free pair. The bool is false when the pool is empty.
// The claim is local bookkeeping: it does not update Wings or the panel DB.
func (p *Pool) Claim() (Pair, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		return Pair{}, false
	}
	pair := p.free[0]
	p.free = p.free[1:]
	return pair, true
}
