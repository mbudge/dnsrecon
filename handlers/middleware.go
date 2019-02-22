package handlers

import (
	"context"
	"fmt"
	"dnsrecon/dnsrecon"
	"net/http"
	"time"
)

type HandlerFunc func(context.Context, http.ResponseWriter, *http.Request) (context.Context, error)

func (s *Server) HandleFunc(handler func(context.Context, http.ResponseWriter, *http.Request) (context.Context, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx := context.Background()
		var err error

		select {
		case dnsClient := <-s.DnsClientChan:

			ctx, err = DnsClientToContext(ctx, dnsClient)
			if err != nil {
				s.Log.Printf("dns client to context: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

		case <-time.After(time.Second * 40):
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		defer func() {
			if err, ok := recover().(error); ok {
				s.Log.Printf("request failed: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		if _, err := handler(ctx, w, r); err != nil {
			s.Log.Printf("request handler failed: %v", err)
			return
		}

		dnsClient, err := DnsClientFromContext(ctx)
		if err != nil {
			s.Log.Printf("failed to get dns client from context: %v", err)
			return
		}

		s.DnsClientChan <- dnsClient

		return
	}
}

func (s *Server) dnsClientToChannel(c *dnsrecon.DnsClient) {
	s.DnsClientChan <- c
}

func DnsClientToContext(ctx context.Context, c *dnsrecon.DnsClient) (context.Context, error) {

	ctx = context.WithValue(ctx, "dnsClient", c)

	return ctx, nil
}

func DnsClientFromContext(ctx context.Context) (*dnsrecon.DnsClient, error) {

	c := ctx.Value("dnsClient")

	dnsClient, ok := c.(*dnsrecon.DnsClient)
	if !ok {
		return dnsClient, fmt.Errorf("dns client not in context")
	}

	return dnsClient, nil
}
