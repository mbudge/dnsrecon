package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

func (s *Server) TargetDomainHandler(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {

	vars := mux.Vars(r)
	domain := vars["domain"]

	dnsClient, err := DnsClientFromContext(ctx)
	if err != nil {
		return ctx, err
	}

	domainData := dnsClient.GetDnsData(domain)

	// Retry a different DNS server if there was an error
	if domainData.Status == "ERROR" {
		select {
		case newDnsClient := <-s.DnsClientChan:

			defer s.dnsClientToChannel(newDnsClient)

			domainData = newDnsClient.GetDnsData(domain)

		case <-time.After(time.Second * 5):
			return ctx, fmt.Errorf("get dns client timeout")
		}
	}

	// TODO validate domainData /errors

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domainData)

	return ctx, nil
}
