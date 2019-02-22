package dnsrecon

import (
	"github.com/miekg/dns"
	"time"
)

func (client *DnsClient) getARecord(domain string, ipv4DataChan chan<- []*dns.A) {

	defer close(ipv4DataChan)

	m := new(dns.Msg)
	m.SetQuestion(fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		// Retry in 500ms
		time.Sleep(time.Millisecond * 500)
		r, err = client.DnsResolver(m)
		if err != nil {
			return
		}
	}

	if r == nil {
		return
	}

	var aset []*dns.A

	for _, aAns := range r.Answer {

		if a, ok := aAns.(*dns.A); ok {
			aset = append(aset, a)
		}
	}

	ipv4DataChan <- aset
}

func (client *DnsClient) getAAAARecord(domain string, ipv6DataChan chan<- []*dns.AAAA) {

	defer close(ipv6DataChan)

	m := new(dns.Msg)
	m.SetQuestion(fqdn(domain), dns.TypeAAAA)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		// Retry in 500ms
		time.Sleep(time.Millisecond * 500)
		r, err = client.DnsResolver(m)
		if err != nil {
			return
		}
	}

	if r == nil {
		return
	}

	var aaaaset []*dns.AAAA

	for _, aaaaAns := range r.Answer {

		if aaaa, ok := aaaaAns.(*dns.AAAA); ok {
			aaaaset = append(aaaaset, aaaa)
		}
	}

	ipv6DataChan <- aaaaset
}
