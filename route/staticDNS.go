package route

import (
	"fmt"
	"net/netip"

	dns "github.com/sagernet/sing-dns"
)

type StaticDNSEntry struct {
	IPv4 *netip.Addr
	IPv6 *netip.Addr
}

func createEntries(items map[string][]string) map[string]StaticDNSEntry {
	entries := make(map[string]StaticDNSEntry)

	for domain, ips := range items {
		entry := StaticDNSEntry{}

		for _, ipString := range ips {
			ip, err := netip.ParseAddr(ipString)
			if err != nil {
				fmt.Printf("Invalid IP address for domain %s: %s\n", domain, ipString)
				continue
			}

			if ip.Is4() {
				entry.IPv4 = &ip
			} else {
				entry.IPv6 = &ip
			}
		}
		entries[domain] = entry
	}

	return entries
}

func lookupStaticIP(domain string, strategy uint8, entries map[string]StaticDNSEntry) ([]netip.Addr, error) {

	if staticDns, ok := entries[domain]; ok {
		addrs := []netip.Addr{}
		switch strategy {
		case dns.DomainStrategyUseIPv4:
			if staticDns.IPv4 != nil {
				addrs = append(addrs, *staticDns.IPv4)
			}
		case dns.DomainStrategyUseIPv6:
			if staticDns.IPv6 != nil {
				addrs = append(addrs, *staticDns.IPv6)
			}
		case dns.DomainStrategyPreferIPv6:
			if staticDns.IPv6 != nil {
				addrs = append(addrs, *staticDns.IPv6)
			}
			if staticDns.IPv4 != nil {
				addrs = append(addrs, *staticDns.IPv4)
			}
		default:
			if staticDns.IPv4 != nil {
				addrs = append(addrs, *staticDns.IPv4)
			}
			if staticDns.IPv6 != nil {
				addrs = append(addrs, *staticDns.IPv6)
			}
		}
		return addrs, nil
	} else {
		return nil, fmt.Errorf("NotFound")
	}

}
