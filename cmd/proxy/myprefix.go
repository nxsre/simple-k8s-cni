package main

import (
	"bytes"
	"encoding/gob"
	goipam "github.com/metal-stack/go-ipam"
	"go4.org/netipx"
	"math"
	"net/netip"
)

// GobEncode implements GobEncode for Prefix
func (p *Prefix) GobEncode() ([]byte, error) {
	w := new(bytes.Buffer)
	encoder := gob.NewEncoder(w)
	if err := encoder.Encode(p.availableChildPrefixes); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.childPrefixLength); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.isParent); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.ips); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.version); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.Cidr); err != nil {
		return nil, err
	}
	if err := encoder.Encode(p.ParentCidr); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// GobDecode implements GobDecode for Prefix
func (p *Prefix) GobDecode(buf []byte) error {
	r := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(r)
	if err := decoder.Decode(&p.availableChildPrefixes); err != nil {
		return err
	}
	if err := decoder.Decode(&p.childPrefixLength); err != nil {
		return err
	}
	if err := decoder.Decode(&p.isParent); err != nil {
		return err
	}
	if err := decoder.Decode(&p.ips); err != nil {
		return err
	}
	if err := decoder.Decode(&p.version); err != nil {
		return err
	}
	if err := decoder.Decode(&p.Cidr); err != nil {
		return err
	}
	return decoder.Decode(&p.ParentCidr)
}

// Prefix is a expression of a ip with length and forms a classless network.
// nolint:musttag
type Prefix struct {
	Cidr                   string          // The Cidr of this prefix
	ParentCidr             string          // if this prefix is a child this is a pointer back
	isParent               bool            // if this Prefix has child prefixes, this is set to true
	availableChildPrefixes map[string]bool // available child prefixes of this prefix
	// TODO remove this in the next release
	childPrefixLength int             // the length of the child prefixes
	ips               map[string]bool // The ips contained in this prefix
	version           int64           // version is used for optimistic locking
}

func (p *Prefix) String() string {
	return p.Cidr
}

// Network return the net.IP part of the Prefix
func (p *Prefix) Network() (netip.Addr, error) {
	ipprefix, err := netip.ParsePrefix(p.Cidr)
	if err != nil {
		return netip.Addr{}, err
	}
	return ipprefix.Addr(), nil
}

// hasIPs will return true if there are allocated IPs
func (p *Prefix) hasIPs() bool {
	ipprefix, err := netip.ParsePrefix(p.Cidr)
	if err != nil {
		return false
	}
	if ipprefix.Addr().Is4() && len(p.ips) > 2 {
		return true
	}
	if ipprefix.Addr().Is6() && len(p.ips) > 1 {
		return true
	}
	return false
}

// availableips return the number of ips available in this Prefix
func (p *Prefix) availableips() uint64 {
	ipprefix, err := netip.ParsePrefix(p.Cidr)
	if err != nil {
		return 0
	}
	// We don't report more than 2^31 available IPs by design
	if (ipprefix.Addr().BitLen() - ipprefix.Bits()) > 31 {
		return math.MaxInt32
	}
	return 1 << (ipprefix.Addr().BitLen() - ipprefix.Bits())
}

// acquiredips return the number of ips acquired in this Prefix
func (p *Prefix) acquiredips() uint64 {
	return uint64(len(p.ips))
}

// availablePrefixes will return the amount of prefixes allocatable and the amount of smallest 2 bit prefixes
func (p *Prefix) availablePrefixes() (uint64, []string) {
	prefix, err := netip.ParsePrefix(p.Cidr)
	if err != nil {
		return 0, nil
	}
	var ipsetBuilder netipx.IPSetBuilder
	ipsetBuilder.AddPrefix(prefix)
	for cp, available := range p.availableChildPrefixes {
		if available {
			continue
		}
		ipprefix, err := netip.ParsePrefix(cp)
		if err != nil {
			continue
		}
		ipsetBuilder.RemovePrefix(ipprefix)
	}

	ipset, err := ipsetBuilder.IPSet()
	if err != nil {
		return 0, []string{}
	}

	// Only 2 Bit Prefixes are usable, set max bits available 2 less than max in family
	maxBits := prefix.Addr().BitLen() - 2
	pfxs := ipset.Prefixes()
	totalAvailable := uint64(0)
	availablePrefixes := []string{}
	for _, pfx := range pfxs {
		bits := maxBits - pfx.Bits()
		if bits < 0 {
			continue
		}
		// same as: totalAvailable += uint64(math.Pow(float64(2), float64(maxBits-pfx.Bits)))
		totalAvailable += 1 << bits
		availablePrefixes = append(availablePrefixes, pfx.String())
	}
	// we are not reporting more that 2^31 available prefixes
	if totalAvailable > math.MaxInt32 {
		totalAvailable = math.MaxInt32
	}
	return totalAvailable, availablePrefixes
}

// acquiredPrefixes return the amount of acquired prefixes of this prefix if this is a parent prefix
func (p *Prefix) acquiredPrefixes() uint64 {
	var count uint64
	for _, available := range p.availableChildPrefixes {
		if !available {
			count++
		}
	}
	return count
}

// Usage report Prefix usage.
func (p *Prefix) Usage() goipam.Usage {
	sp, ap := p.availablePrefixes()
	return goipam.Usage{
		AvailableIPs:              p.availableips(),
		AcquiredIPs:               p.acquiredips(),
		AcquiredPrefixes:          p.acquiredPrefixes(),
		AvailableSmallestPrefixes: sp,
		AvailablePrefixes:         ap,
	}
}
