package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"dnsrecon/config"
	"dnsrecon/dnsrecon"
	"dnsrecon/handlers"
	"dnsrecon/logging"
	"dnsrecon/resolvers"
	"log"
	"net/http"
	"time"
)

func main() {

	s := handlers.Server{}

	resolvers.CreateResolversFile()

	created := config.CreateConfig()
	if created {
		return
	}
	s.Config = config.LoadConfig()

	resolvers := resolvers.LoadResolvers()

	cache := dnsrecon.NewLruCache()

	s.Log = logging.NewLogger()

	s.DnsClientChan = make(chan *dnsrecon.DnsClient, len(resolvers.DnsServers))
	rCount := 0

	// Load the resolvers
	for _, resolver := range resolvers.DnsServers {
		if rCount != 0 && rCount == s.Config.MaximumDnsServers {
			break
		}
		client := dnsrecon.NewDnsClient()
		client.Resolver = resolver
		client.RetryResolvers = resolvers.RetryServers
		client.Ratelimit = resolver.Ratelimit
		client.Cache = cache
		client.Log = logging.NewLogger()
		client.Start()
		s.DnsClientChan <- client

		rCount++
	}

	fmt.Printf("Using %d public dns servers\n", rCount)

	//  Clear the LRU cache every 24 hours
	go func() {
		for range time.Tick(time.Hour * 24) {

			cache.Mu.Lock()
			cache.Lru.Clear()
			cache.Mu.Unlock()
		}
	}()

	r := mux.NewRouter()

	r.HandleFunc("/", healthCheckHandler)

	r.Path("/domain/{domain}").Methods("GET").HandlerFunc(s.HandleFunc(s.TargetDomainHandler))

	fmt.Println("Listening on port 8080")

	http.Handle("/", r)

	srv := &http.Server{
		ReadTimeout:  80 * time.Second,
		WriteTimeout: 80 * time.Second,
		Addr:         ":8080",
	}

	log.Fatal(srv.ListenAndServe())

}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}
