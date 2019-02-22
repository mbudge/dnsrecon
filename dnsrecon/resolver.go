package dnsrecon

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

func (client *DnsClient) DnsResolver(m *dns.Msg) (*dns.Msg, error) {

	r := new(dns.Msg)
	var err error

	key := fmt.Sprintf("%s:%d", m.Question[0].Name, m.Question[0].Qtype)

	client.Cache.Mu.Lock()
	rFromCache, ok := client.Cache.Lru.Get(key)
	client.Cache.Mu.Unlock()

	if ok && rFromCache != nil {
		return rFromCache.(*dns.Msg), nil
	}

	var dnsserver string

	for i := 0; i != 3; i++ {

		err = nil

		client.RatelimitRequests()

		// get a new dns server if the first retry failed
		if i == 2 {
			dnsserver = client.GetRetryDnsServer()
		} else {
			dnsserver = client.GetNameserver()
		}

		// Check whether the error is retryable
		r, _, err = client.dns.Exchange(m, dnsserver)
		if err != nil {
			if te, ok := err.(interface{ Temporary() bool }); ok {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					err = fmt.Errorf("TIMEOUT")
					// Retryable
					continue
				} else if te.Temporary() {
					// Retryable
					continue
				} else {
					// Non-retryable
					return nil, fmt.Errorf("ERROR")
				}
			}
		}

		switch r.Rcode {
		case dns.RcodeSuccess:
			err = nil
		case dns.RcodeNameError:
			return nil, fmt.Errorf("NXDOMAIN")
		case dns.RcodeNotImplemented:
			return nil, fmt.Errorf("NOTIMP")
		case dns.RcodeYXDomain:
			return nil, fmt.Errorf("YXDOMAIN")
		case dns.RcodeNXRrset:
			return nil, fmt.Errorf("NXRRSET")
		case dns.RcodeYXRrset:
			return nil, fmt.Errorf("YXRRSET")
		case dns.RcodeNotZone:
			return nil, fmt.Errorf("NOTZONE")
		case dns.RcodeNotAuth:
			return nil, fmt.Errorf("NOTAUTH")
		case dns.RcodeBadName:
			return nil, fmt.Errorf("BADNAME")
		case dns.RcodeBadTrunc:
			return nil, fmt.Errorf("BADTRUNC")
		case dns.RcodeServerFailure:
			return nil, fmt.Errorf("SERVFAIL")
		case dns.RcodeRefused:
			return nil, fmt.Errorf("REFUSED")
		default:
			err = fmt.Errorf("ERROR")
		}

		if err != nil {
			continue
		}

		break
	}

	if r != nil && r.Rcode == dns.RcodeSuccess {
		client.Cache.Mu.Lock()
		client.Cache.Lru.Add(key, r)
		client.Cache.Mu.Unlock()
	}

	if err != nil {
		client.Log.Printf("dns resolver error: %v", err)
	}

	return r, err

}
