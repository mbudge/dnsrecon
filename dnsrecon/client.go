package dnsrecon

import (
	"context"
	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
	"dnsrecon/resolvers"
	"golang.org/x/time/rate"
	"log"
	"math/rand"
	"sync"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type TargetLookup struct {
	Domain       string
	DomainDataCh chan DomainData
}

type LruCache struct {
	Lru *lru.Cache
	Mu  sync.RWMutex
}

func NewLruCache() *LruCache {
	var lrucache LruCache
	lrucache.Lru = NewCache()
	return &lrucache
}

type DnsClient struct {
	dns            *dns.Client
	Resolver       *resolvers.Resolver
	RetryResolvers *resolvers.RetryResolver
	limiter        *rate.Limiter
	TargetLookupCh chan TargetLookup
	ClientId       int
	Cache          *LruCache
	Log            *log.Logger
	Ratelimit      int
	Nameserver     string
	Nameservers    struct {
		Ips   []string
		mu    sync.Mutex
		i     int
		total int
	}

	mu     sync.Mutex
	muRate sync.Mutex
	ctx    context.Context
}

func NewDnsClient() *DnsClient {

	var dnsClient DnsClient

	dnsClient.dns = &dns.Client{}

	return &dnsClient
}

func NewCache() *lru.Cache {
	return lru.New(10000)
}

func (client *DnsClient) Start() {

	r := rate.Limit(client.Resolver.Ratelimit)

	client.limiter = rate.NewLimiter(r, 5)

	client.dns.Timeout = time.Second * 10

	client.Nameservers.Ips = append(client.Nameservers.Ips, client.Resolver.Ips...)

	client.Nameservers.total = len(client.Nameservers.Ips)

	client.ctx = context.Background()
}

func (client *DnsClient) RatelimitRequests() {

	err := client.limiter.WaitN(client.ctx, 1)
	if err != nil {
		client.Log.Printf("rate limit error: %v", err)
	}
}

func (client *DnsClient) GetNameserver() string {

	client.Nameservers.mu.Lock()

	if client.Nameservers.i == client.Nameservers.total {
		client.Nameservers.i = 0
	}

	server := client.Nameservers.Ips[client.Nameservers.i]
	client.Nameservers.i++

	client.Nameservers.mu.Unlock()

	return server

}

func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

func (client *DnsClient) GetRetryDnsServer() string {
	i := random(1, len(client.RetryResolvers.Ips))
	return client.RetryResolvers.Ips[i]
}
