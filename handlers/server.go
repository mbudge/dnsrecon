package handlers

import (
	"dnsrecon/config"
	"dnsrecon/dnsrecon"
	"log"
)

type Server struct {
	DnsClientChan chan *dnsrecon.DnsClient
	Config        *config.Config
	Log           *log.Logger
}
