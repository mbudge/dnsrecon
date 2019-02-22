package dnsrecon

import (
	"time"
)

func (client *DnsClient) GetDnsData(targetDomain string) *DomainData {

	soaDataChan := make(chan soaResponse, 1)
	aDataChan := make(chan aResponse, 1)
	aaaaDataChan := make(chan aaaaResponse, 1)
	nsDataChan := make(chan nsResponse, 1)
	mxDataChan := make(chan mxResponse, 1)
	txtDataChan := make(chan txtResponse, 1)
	cnameDataChan := make(chan cnameResponse, 1)

	domainData := NewDomainData()
	domainData.Name = targetDomain
	domainData.Timestamp = time.Now().UTC()
	domainData.Status = "NOERROR"

	// Check the SOA, A and AAAA records before returned domainData with an error
	// Some misconfigured domains return no SOA record but return A/AAAA records
	// Unless the dns request failed causing no SOA record to be returned
	// All valid domains have an SOA record
	go client.getSOA(targetDomain, soaDataChan, domainData)
	go client.getA(targetDomain, aDataChan, domainData)
	go client.getAAAA(targetDomain, aaaaDataChan, domainData)

	// Check the SOA record first as only valid domains have an SOA
	for soaResponse := range soaDataChan {

		if soaResponse.Error != nil {
			domainData.Errors["soa"] = soaResponse.Error.Error()
		}
		domainData.Data.SOA = soaResponse.SOA
	}

	for aResponse := range aDataChan {

		if aResponse.Error != nil {
			domainData.Errors["a"] = aResponse.Error.Error()
		}
		domainData.Data.A = aResponse.A
	}

	for aaaaResponse := range aaaaDataChan {

		if aaaaResponse.Error != nil {
			domainData.Errors["aaaa"] = aaaaResponse.Error.Error()
		}
		domainData.Data.AAAA = aaaaResponse.AAAA
	}

	// Check domainData for errors
	if len(domainData.Data.A) == 0 && len(domainData.Data.AAAA) == 0 && len(domainData.Data.SOA.Nameserver) == 0 {

		_, soaErr := domainData.Errors["soa"]
		if soaErr {
			domainData.Status = domainData.Errors["soa"]
			return domainData
		}
		_, aErr := domainData.Errors["a"]
		if aErr {
			domainData.Status = domainData.Errors["a"]
			return domainData
		}
		_, aaaaErr := domainData.Errors["aaaa"]
		if aaaaErr {
			domainData.Status = domainData.Errors["aaaa"]
			return domainData
		}

		// Return if no SOA, A or AAAA records were found without wasting time doing other lookups
		domainData.Status = "ERROR"
		return domainData
	}

	// Do lookups for other reocords if SOA, A or AAAA lookups found data
	go client.getNS(targetDomain, nsDataChan, domainData)
	go client.getMX(targetDomain, mxDataChan, domainData)
	go client.getTXT(targetDomain, txtDataChan, domainData)
	go client.getCNAME(targetDomain, cnameDataChan, domainData)

	for nsResponse := range nsDataChan {

		if nsResponse.Error != nil {
			domainData.Errors["ns"] = nsResponse.Error.Error()
		}
		domainData.Data.NS = nsResponse.NS
	}

	for mxResponse := range mxDataChan {

		if mxResponse.Error != nil {
			domainData.Errors["mx"] = mxResponse.Error.Error()
		}
		domainData.Data.MX = mxResponse.MX
	}

	for txtResponse := range txtDataChan {

		if txtResponse.Error != nil {
			domainData.Errors["txt"] = txtResponse.Error.Error()
		}
		domainData.Data.TXT = txtResponse.TXT
	}

	for cnameResponse := range cnameDataChan {

		if cnameResponse.Error != nil {
			domainData.Errors["cname"] = cnameResponse.Error.Error()
		}
		domainData.Data.CName = cnameResponse.CName
	}

	return domainData

}

func (dns *DomainData) Validate() bool {

	if dns.Data.SOA.Name != "" && len(dns.Data.SOA.Nameserver) > 0 {
		return true
	}
	if len(dns.Data.NS) > 0 {
		return true
	}
	if len(dns.Data.MX) > 0 {
		return true
	}
	if len(dns.Data.A) > 0 {
		return true
	}
	if len(dns.Data.AAAA) > 0 {
		return true
	}
	if len(dns.Data.CName) > 0 {
		return true
	}
	if len(dns.Data.TXT) > 0 {
		return true
	}
	return false
}

// DomainData stored the full set of dns records for the domain
type DomainData struct {
	Name string `json:"name"`

	Data struct {
		SOA        soaData                  `json:"soa"`
		NS         map[string]IpSet         `json:"ns"`
		MX         map[int]map[string]IpSet `json:"mx"`
		TXT        []string                 `json:"txt"`
		CName      []string                 `json:"cname"`
		A          []string                 `json:"a"`
		AAAA       []string                 `json:"aaaa"`
		CNamePaths map[string][][]string    `json:"cname_paths"`
	} `json:"data"`

	Timestamp time.Time `json:"timestamp"`

	Status string `json:"status"`

	Errors map[string]string `json:"errors"`
}

// soaData, MXData, NSData and IpSet are used in the response from various goroutines
type soaData struct {
	Name       string           `json:"name"`
	Nameserver map[string]IpSet `json:"primary_nameserver"`
	MBox       string           `json:"mbox"`
}

type MXData struct {
	MX map[int]map[string]IpSet
}

type NSData struct {
	NS map[string]IpSet `json:"ns"`
}

type IpSet struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
}

func NewDomainData() *DomainData {

	var domainData DomainData

	var soa soaData
	soa.Nameserver = make(map[string]IpSet)
	domainData.Data.SOA = soa

	domainData.Data.NS = make(map[string]IpSet, 0)
	domainData.Data.MX = make(map[int]map[string]IpSet, 0)
	domainData.Data.TXT = make([]string, 0)
	domainData.Data.CName = make([]string, 0)
	domainData.Data.A = make([]string, 0)
	domainData.Data.AAAA = make([]string, 0)
	domainData.Data.CNamePaths = make(map[string][][]string, 0)
	domainData.Errors = make(map[string]string, 0)

	return &domainData
}

// The following store dns sets and error codes seen during lookups
type soaResponse struct {
	SOA   soaData
	Error error
}

type nsResponse struct {
	NS    map[string]IpSet
	Error error
}

type mxResponse struct {
	MX    map[int]map[string]IpSet
	Error error
}

type txtResponse struct {
	TXT   []string
	Error error
}

type cnameResponse struct {
	CName []string
	Error error
}

type aResponse struct {
	A     []string
	Error error
}

type aaaaResponse struct {
	AAAA  []string
	Error error
}
