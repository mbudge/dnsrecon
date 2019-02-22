package dnsrecon

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

const (
	ErrNoData = "NODATA"
)

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimRight(d, "."))
}

func fqdn(d string) string {
	return fmt.Sprintf("%s.", strings.ToLower(strings.TrimRight(d, ".")))
}

func newIpSet() IpSet {

	var ipset IpSet
	ipset.A = make([]string, 0)
	ipset.AAAA = make([]string, 0)
	return ipset
}

func (client *DnsClient) getSOA(targetDomain string, soaDataChan chan<- soaResponse, domainData *DomainData) {

	defer close(soaDataChan)

	var response soaResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeSOA)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		// Retry in 500ms
		time.Sleep(time.Millisecond * 500)
		r, err = client.DnsResolver(m)
	}

	if err != nil {
		response.Error = err
		soaDataChan <- response
		return
	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		soaDataChan <- response
		return
	}

	var cnamePaths []string
	var ipv4DataChannels []chan []*dns.A
	var ipv6DataChannels []chan []*dns.AAAA

	var soaData soaData
	soaData.Nameserver = make(map[string]IpSet, 0)
	finalCNameName := false

	for _, soaAns := range r.Answer {

		if cname, ok := soaAns.(*dns.CNAME); ok {
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Header().Name))
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Target))
		}

		if soa, ok := soaAns.(*dns.SOA); ok {
			soaData.MBox = normalizeDomain(soa.Mbox)
			soaData.Name = normalizeDomain(soa.Header().Name)

			if len(cnamePaths) > 0 {
				if !finalCNameName {
					cnamePaths = append(cnamePaths, normalizeDomain(soa.Header().Name))
					finalCNameName = true
				}
				cnamePaths = append(cnamePaths, normalizeDomain(soa.Ns))
			}

			ipv4DataChan := make(chan []*dns.A, 1)
			ipv6DataChan := make(chan []*dns.AAAA, 1)
			go client.getARecord(soa.Ns, ipv4DataChan)
			go client.getAAAARecord(soa.Ns, ipv6DataChan)
			ipv4DataChannels = append(ipv4DataChannels, ipv4DataChan)
			ipv6DataChannels = append(ipv6DataChannels, ipv6DataChan)

			soaData.Nameserver[normalizeDomain(soa.Ns)] = newIpSet()

		}
	}

	// Check DNS Authority Section if the CNAME path did not end in an SOA record
	if soaData.Name == "" {

		for _, soaAns := range r.Ns {

			if soa, ok := soaAns.(*dns.SOA); ok {

				soaData.MBox = normalizeDomain(soa.Mbox)
				soaData.Name = normalizeDomain(soa.Header().Name)

				ipv4DataChan := make(chan []*dns.A, 1)
				ipv6DataChan := make(chan []*dns.AAAA, 1)
				go client.getARecord(soa.Ns, ipv4DataChan)
				go client.getAAAARecord(soa.Ns, ipv6DataChan)
				ipv4DataChannels = append(ipv4DataChannels, ipv4DataChan)
				ipv6DataChannels = append(ipv6DataChannels, ipv6DataChan)

				soaData.Nameserver[normalizeDomain(soa.Ns)] = newIpSet()

			}
		}
	}

	for _, ipv4DataChan := range ipv4DataChannels {

		for ipv4Ans := range ipv4DataChan {
			for _, ipv4 := range ipv4Ans {
				primary_ns := normalizeDomain(ipv4.Header().Name)
				soa, ok := soaData.Nameserver[primary_ns]
				if !ok {
					continue
				}
				soa.A = append(soa.A, ipv4.A.String())
				soaData.Nameserver[primary_ns] = soa

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv4.A.String())
				}
			}
		}
	}

	for _, ipv6DataChan := range ipv6DataChannels {

		for ipv6Ans := range ipv6DataChan {
			for _, ipv6 := range ipv6Ans {
				primary_ns := normalizeDomain(ipv6.Header().Name)
				soa, ok := soaData.Nameserver[primary_ns]
				if !ok {
					continue
				}
				soa.AAAA = append(soa.AAAA, ipv6.AAAA.String())
				soaData.Nameserver[primary_ns] = soa

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv6.AAAA.String())
				}
			}
		}
	}

	client.mu.Lock()
	if len(cnamePaths) > 0 {
		if len(domainData.Data.CNamePaths["soa"]) > 0 {
			newCNamePaths := make([][]string, len(domainData.Data.CNamePaths["soa"])+1)
			for i, CNamePath := range domainData.Data.CNamePaths["soa"] {
				newCNamePaths[i] = CNamePath
			}
			domainData.Data.CNamePaths["soa"][len(domainData.Data.CNamePaths["soa"])+1] = cnamePaths
			domainData.Data.CNamePaths["soa"] = newCNamePaths
		} else {
			domainData.Data.CNamePaths["soa"] = make([][]string, 1)
			domainData.Data.CNamePaths["soa"][0] = cnamePaths
		}
	}
	client.mu.Unlock()

	response.SOA = soaData

	soaDataChan <- response
}

func (client *DnsClient) getNS(targetDomain string, nsDataChan chan<- nsResponse, domainData *DomainData) {

	// fmt.Println(targetDomain)
	defer close(nsDataChan)

	var response nsResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeNS)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		nsDataChan <- response
		return
	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		nsDataChan <- response
		return
	}

	var nsSet = make(map[string]IpSet)
	var ipv4DataChannels []chan []*dns.A
	var ipv6DataChannels []chan []*dns.AAAA

	var cnamePaths []string
	finalCNameName := false

	for _, nsAns := range r.Answer {

		if cname, ok := nsAns.(*dns.CNAME); ok {
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Header().Name))
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Target))
		}

		if ns, ok := nsAns.(*dns.NS); ok {
			if len(cnamePaths) > 0 {
				if !finalCNameName {
					cnamePaths = append(cnamePaths, normalizeDomain(ns.Header().Name))
					finalCNameName = true
				}
				cnamePaths = append(cnamePaths, normalizeDomain(ns.Ns))
			}

			ipv4DataChan := make(chan []*dns.A, 1)
			ipv6DataChan := make(chan []*dns.AAAA, 1)
			go client.getARecord(ns.Ns, ipv4DataChan)
			go client.getAAAARecord(ns.Ns, ipv6DataChan)
			ipv4DataChannels = append(ipv4DataChannels, ipv4DataChan)
			ipv6DataChannels = append(ipv6DataChannels, ipv6DataChan)

			nsSet[normalizeDomain(ns.Ns)] = newIpSet()

		}
	}

	for _, ipv4DataChan := range ipv4DataChannels {
		for ipv4Ans := range ipv4DataChan {
			for _, ipv4 := range ipv4Ans {
				ns, ok := nsSet[normalizeDomain(ipv4.Header().Name)]
				if !ok {
					continue
				}

				ns.A = append(ns.A, ipv4.A.String())
				nsSet[normalizeDomain(ipv4.Header().Name)] = ns

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv4.A.String())
				}
			}
		}
	}

	for _, ipv6DataChan := range ipv6DataChannels {
		for ipv6Ans := range ipv6DataChan {
			for _, ipv6 := range ipv6Ans {
				ns, ok := nsSet[normalizeDomain(ipv6.Header().Name)]
				if !ok {
					continue
				}
				ns.AAAA = append(ns.AAAA, ipv6.AAAA.String())
				nsSet[normalizeDomain(ipv6.Header().Name)] = ns

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv6.AAAA.String())
				}
			}
		}
	}

	client.mu.Lock()
	if len(cnamePaths) > 0 {
		if len(domainData.Data.CNamePaths["ns"]) > 0 {
			newCNamePaths := make([][]string, len(domainData.Data.CNamePaths["ns"])+1)
			for i, CNamePath := range domainData.Data.CNamePaths["ns"] {
				newCNamePaths[i] = CNamePath
			}
			domainData.Data.CNamePaths["ns"][len(domainData.Data.CNamePaths["ns"])+1] = cnamePaths
			domainData.Data.CNamePaths["ns"] = newCNamePaths
		} else {
			domainData.Data.CNamePaths["ns"] = make([][]string, 1)
			domainData.Data.CNamePaths["ns"][0] = cnamePaths
		}
	}
	client.mu.Unlock()

	response.NS = nsSet

	nsDataChan <- response
}

func (client *DnsClient) getMX(targetDomain string, mxDataChan chan<- mxResponse, domainData *DomainData) {

	defer close(mxDataChan)

	var response mxResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeMX)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		mxDataChan <- response
		return

	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		mxDataChan <- response
		return
	}

	var mxSet = make(map[int]map[string]IpSet)
	var ipv4DataChannels []chan []*dns.A
	var ipv6DataChannels []chan []*dns.AAAA

	var cnamePaths []string
	finalCNameName := false

	for _, mxAns := range r.Answer {

		if cname, ok := mxAns.(*dns.CNAME); ok {
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Header().Name))
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Target))
		}

		if mx, ok := mxAns.(*dns.MX); ok {
			if len(cnamePaths) > 0 {
				if !finalCNameName {
					cnamePaths = append(cnamePaths, normalizeDomain(mx.Header().Name))
					finalCNameName = true
				}
				cnamePaths = append(cnamePaths, normalizeDomain(mx.Mx))
			}

			ipv4DataChan := make(chan []*dns.A, 1)
			ipv6DataChan := make(chan []*dns.AAAA, 1)
			go client.getARecord(mx.Mx, ipv4DataChan)
			go client.getAAAARecord(mx.Mx, ipv6DataChan)
			ipv4DataChannels = append(ipv4DataChannels, ipv4DataChan)
			ipv6DataChannels = append(ipv6DataChannels, ipv6DataChan)

			mxdata, ok := mxSet[int(mx.Preference)]
			if !ok {
				mxdata = make(map[string]IpSet)
			}
			mxdata[normalizeDomain(mx.Mx)] = newIpSet()
			mxSet[int(mx.Preference)] = mxdata
		}
	}

	for _, ipv4DataChan := range ipv4DataChannels {
		for ipv4Ans := range ipv4DataChan {
			for _, ipv4 := range ipv4Ans {
				for _, preference := range mxSet {

					mxdata, ok := preference[normalizeDomain(ipv4.Header().Name)]
					if !ok {
						continue
					}
					mxdata.A = append(mxdata.A, ipv4.A.String())
					preference[normalizeDomain(ipv4.Header().Name)] = mxdata
				}

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv4.A.String())
				}
			}
		}
	}

	for _, ipv6DataChan := range ipv6DataChannels {
		for ipv6Ans := range ipv6DataChan {
			for _, ipv6 := range ipv6Ans {
				for _, preference := range mxSet {

					mxdata, ok := preference[normalizeDomain(ipv6.Header().Name)]
					if !ok {
						continue
					}
					mxdata.AAAA = append(mxdata.AAAA, ipv6.AAAA.String())
					preference[normalizeDomain(ipv6.Header().Name)] = mxdata
				}

				if len(cnamePaths) > 0 {
					cnamePaths = append(cnamePaths, ipv6.AAAA.String())
				}
			}
		}
	}

	client.mu.Lock()
	if len(cnamePaths) > 0 {
		if len(domainData.Data.CNamePaths["mx"]) > 0 {
			newCNamePaths := make([][]string, len(domainData.Data.CNamePaths["mx"])+1)
			for i, CNamePath := range domainData.Data.CNamePaths["mx"] {
				newCNamePaths[i] = CNamePath
			}
			domainData.Data.CNamePaths["mx"][len(domainData.Data.CNamePaths["mx"])+1] = cnamePaths
			domainData.Data.CNamePaths["mx"] = newCNamePaths
		} else {
			domainData.Data.CNamePaths["mx"] = make([][]string, 1)
			domainData.Data.CNamePaths["mx"][0] = cnamePaths
		}
	}
	client.mu.Unlock()

	response.MX = mxSet

	mxDataChan <- response
}

func (client *DnsClient) getTXT(targetDomain string, txtDataChan chan<- txtResponse, domainData *DomainData) {

	// fmt.Println(targetDomain)
	defer close(txtDataChan)

	var response txtResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeTXT)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		txtDataChan <- response
		return

	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		txtDataChan <- response
		return
	}

	var txtSet []string

	for _, txtAns := range r.Answer {

		if txt, ok := txtAns.(*dns.TXT); ok {

			txtSet = append(txtSet, txt.Txt...)
		}
	}

	response.TXT = txtSet

	txtDataChan <- response
}

func (client *DnsClient) getCNAME(targetDomain string, cnameDataChan chan<- cnameResponse, domainData *DomainData) {

	defer close(cnameDataChan)

	var response cnameResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeCNAME)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		cnameDataChan <- response
		return

	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		cnameDataChan <- response
		return
	}

	var cnameSet []string

	for _, cnameAns := range r.Answer {

		if cname, ok := cnameAns.(*dns.CNAME); ok {

			cnameSet = append(cnameSet, cname.Target)
		}
	}

	response.CName = cnameSet

	cnameDataChan <- response
}

func (client *DnsClient) getA(targetDomain string, aDataChan chan<- aResponse, domainData *DomainData) {

	// fmt.Println(targetDomain)
	defer close(aDataChan)

	var response aResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeA)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		aDataChan <- response
		return
	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		aDataChan <- response
		return
	}

	var aSet []string
	var cnamePaths []string
	finalCNameName := false

	for _, aAns := range r.Answer {

		if cname, ok := aAns.(*dns.CNAME); ok {
			cnamePaths = append(cnamePaths, cname.Header().Name)
			cnamePaths = append(cnamePaths, normalizeDomain(cname.Target))
		}

		if a, ok := aAns.(*dns.A); ok {
			if len(cnamePaths) > 0 {
				if !finalCNameName {
					cnamePaths = append(cnamePaths, normalizeDomain(a.Header().Name))
					finalCNameName = true
				}
				cnamePaths = append(cnamePaths, a.A.String())
			}
			aSet = append(aSet, a.A.String())
		}
	}

	client.mu.Lock()
	// TODO improve check a
	if len(cnamePaths) > 0 {

		if len(domainData.Data.CNamePaths["a"]) > 0 {
			newCNamePaths := make([][]string, len(domainData.Data.CNamePaths["a"])+1)
			for i, CNamePath := range domainData.Data.CNamePaths["a"] {
				newCNamePaths[i] = CNamePath
			}
			domainData.Data.CNamePaths["a"][len(domainData.Data.CNamePaths["a"])+1] = cnamePaths
			domainData.Data.CNamePaths["a"] = newCNamePaths
		} else {
			domainData.Data.CNamePaths["a"] = make([][]string, 1)
			domainData.Data.CNamePaths["a"][0] = cnamePaths
		}
	}
	client.mu.Unlock()

	response.A = aSet

	aDataChan <- response
}

func (client *DnsClient) getAAAA(targetDomain string, aaaaDataChan chan<- aaaaResponse, domainData *DomainData) {

	// fmt.Println(targetDomain)

	defer close(aaaaDataChan)

	var response aaaaResponse

	m := new(dns.Msg)
	m.SetQuestion(fqdn(targetDomain), dns.TypeAAAA)
	m.RecursionDesired = true

	r, err := client.DnsResolver(m)
	if err != nil {
		response.Error = err
		aaaaDataChan <- response
		return
	}

	if r == nil {
		response.Error = fmt.Errorf(ErrNoData)
		aaaaDataChan <- response
		return
	}

	var aaaaSet []string

	var cnamePaths []string
	finalCNameName := false

	for _, aaaaAns := range r.Answer {

		if cname, ok := aaaaAns.(*dns.CNAME); ok {
			cnamePaths = append(cnamePaths, cname.Header().Name)
			cnamePaths = append(cnamePaths, cname.Target)
		}

		if aaaa, ok := aaaaAns.(*dns.AAAA); ok {
			if len(cnamePaths) > 0 {
				if !finalCNameName {
					cnamePaths = append(cnamePaths, normalizeDomain(aaaa.Header().Name))
					finalCNameName = true
				}
				cnamePaths = append(cnamePaths, aaaa.AAAA.String())
			}
			aaaaSet = append(aaaaSet, aaaa.AAAA.String())

		}
	}

	client.mu.Lock()
	if len(cnamePaths) > 0 {
		if len(domainData.Data.CNamePaths["aaaa"]) > 0 {
			newCNamePaths := make([][]string, len(domainData.Data.CNamePaths["aaaa"])+1)
			for i, CNamePath := range domainData.Data.CNamePaths["aaaa"] {
				newCNamePaths[i] = CNamePath
			}
			domainData.Data.CNamePaths["aaaa"][len(domainData.Data.CNamePaths["aaaa"])+1] = cnamePaths
			domainData.Data.CNamePaths["aaaa"] = newCNamePaths
		} else {
			domainData.Data.CNamePaths["aaaa"] = make([][]string, 1)
			domainData.Data.CNamePaths["aaaa"][0] = cnamePaths
		}
	}
	client.mu.Unlock()

	response.AAAA = aaaaSet

	aaaaDataChan <- response
}
