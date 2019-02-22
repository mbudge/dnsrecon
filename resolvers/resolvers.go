package resolvers

func (r *Resolvers) Add(nameserver string, ips []string, ratelimit int) {

	dns := Resolver{
		Nameserver: nameserver,
		Ratelimit:  ratelimit,
		Enable:     true,
	}
	dns.Ips = append(dns.Ips, ips...)
	r.DnsServers = append(r.DnsServers, &dns)
}

func (r *Resolvers) AddRetryServers(nameserver string, ips []string, ratelimit int) {

	dns := RetryResolver{
		Nameserver: nameserver,
		Ratelimit:  ratelimit,
		Enable:     true,
	}
	dns.Ips = append(dns.Ips, ips...)
	r.RetryServers = &dns
}

func (r *Resolvers) AddNameservers() {

	retryServers := []string{"109.228.17.201:53", "109.228.0.46:53", "194.72.73.131:53", "78.109.175.227:53", "213.171.206.59:53", "213.171.206.197:53", "213.171.206.141:53", "109.233.47.19:53", "109.228.8.83:53", "109.228.8.167:53", "213.171.206.194:53", "109.228.2.168:53", "109.228.2.155:53", "193.26.23.55:53", "88.208.228.34:53", "77.68.46.58:53", "213.171.206.48:53", "109.228.0.46:53", "88.208.192.80:53"}

	r.AddRetryServers("Retry Pool Dns Servers", retryServers, 20)

	r.Add("google", []string{"8.8.8.8:53", "8.8.4.4:53"}, 40)

	r.Add("google", []string{"8.8.8.8:53", "8.8.4.4:53"}, 40)

	r.Add("comodo secure dns", []string{"8.26.56.26:53", "8.10.247.10:53"}, 10)

	r.Add("level3", []string{"109.244.0.3:53", "109.244.0.4:53"}, 10)

	r.Add("verisign", []string{"64.6.64.6:53", "64.6.65.6:53"}, 10)

	r.Add("dns advantage", []string{"156.154.70.1:53", "156.154.71.1:53"}, 5)

	r.Add("opennic", []string{"198.106.14.241:53", "172.98.193.42:53"}, 10)

	r.Add("dyn", []string{"216.146.35.35:53", "216.146.36.36:53"}, 10)

	r.Add("dns watch", []string{"84.100.69.80:53", "84.100.70.40:53"}, 10)

	r.Add("quad9", []string{"9.9.9.9:53", "149.112.112.112:53"}, 10)

	r.Add("green team dns", []string{"81.218.119.11:53", "109.88.198.133:53"}, 10)

	r.Add("safedns", []string{"195.46.39.39:53", "195.46.39.40:53"}, 10)

	r.Add("smartviper", []string{"108.76.50.50:53", "108.76.51.51:53"}, 10)

	r.Add("freedns", []string{"45.33.97.5:53", "37.235.1.177:53"}, 10)

	r.Add("alternate dns", []string{"198.101.242.72:53", "23.253.163.53:53"}, 10)

	r.Add("yandex.dns", []string{"77.88.8.8:53", "77.88.8.1:53"}, 10)

	r.Add("uncensored dns", []string{"91.239.100.100:53", "89.233.43.71:53"}, 10)

	r.Add("neustar", []string{"156.154.70.1:53", "156.154.71.1:53"}, 10)

	r.Add("clean browsing", []string{"185.228.168.9:53", "185.228.169.9:53"}, 10)

	r.Add("tenta", []string{"99.192.182.100:53", "99.192.182.101:53"}, 10)

}
