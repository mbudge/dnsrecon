# DNSRECON

DNSRECON is a prototype REST API to do dns reconnaissance and collect the complete set of SOA, NS, MX, A, AAAA, TXT and CNAME reconds. More dns records and features will be added after the tool is productionised later this year.

Warning: not for production use

## Install

DNSRECON can be installed by running:

```
go get github.com/mbudge/dnsrecon 
```

## Prerequisites

DNSRECON requires the following dependencies:

```
go get github.com/miekg/dns
go get github.com/gorilla/mux
go get golang.org/x/time/rate
go get github.com/golang/groupcache/lru
``` 

## Usage

Add more public dns servers to resolvers.yaml before increasing the number of concurrent queries.

### Run locally

```
cd dnsrecon
go run *.go
```

### Build and install

```
go install dnsrecon
curl http://127.0.0.1:8080/domain/google.com
```

### Docker 

#### Build 

```
cd dnsrecon
docker build --rm -t "dnsrecon" .
```

#### Run 

```
docker run -d -p 8080:8080 --restart=unless-stopped --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 --name dnsrecon dnsrecon
```

## Example

```
curl http://127.0.0.1:8080/domain/google.com | json_pp
{
   "timestamp" : "2019-02-22T11:10:16.83421805Z",
   "status" : "NOERROR",
   "errors" : {},
   "name" : "google.com",
   "data" : {
      "txt" : [
         "v=spf1 include:_spf.google.com ~all",
         "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95",
         "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=",
         "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
      ],
      "soa" : {
         "mbox" : "dns-admin.google.com",
         "name" : "google.com",
         "primary_nameserver" : {
            "ns1.google.com" : {
               "a" : [
                  "216.239.32.10"
               ],
               "aaaa" : [
                  "2001:4860:4802:32::a"
               ]
            }
         }
      },
      "mx" : {
         "20" : {
            "alt1.aspmx.l.google.com" : {
               "a" : [
                  "74.125.131.27"
               ],
               "aaaa" : [
                  "2a00:1450:4010:c0e::1a"
               ]
            }
         },
         "50" : {
            "alt4.aspmx.l.google.com" : {
               "a" : [
                  "74.125.195.27"
               ],
               "aaaa" : [
                  "2607:f8b0:400e:c09::1b"
               ]
            }
         },
         "30" : {
            "alt2.aspmx.l.google.com" : {
               "a" : [
                  "74.125.68.27"
               ],
               "aaaa" : [
                  "2404:6800:4003:c02::1a"
               ]
            }
         },
         "40" : {
            "alt3.aspmx.l.google.com" : {
               "a" : [
                  "64.233.188.26"
               ],
               "aaaa" : [
                  "2404:6800:4008:c06::1b"
               ]
            }
         },
         "10" : {
            "aspmx.l.google.com" : {
               "aaaa" : [
                  "2a00:1450:400c:c00::1a"
               ],
               "a" : [
                  "108.177.15.27"
               ]
            }
         }
      },
      "aaaa" : [
         "2a00:1450:4009:811::200e"
      ],
      "cname" : null,
      "a" : [
         "216.58.206.142"
      ],
      "ns" : {
         "ns2.google.com" : {
            "aaaa" : [
               "2001:4860:4802:34::a"
            ],
            "a" : [
               "216.239.34.10"
            ]
         },
         "ns3.google.com" : {
            "aaaa" : [
               "2001:4860:4802:36::a"
            ],
            "a" : [
               "216.239.36.10"
            ]
         },
         "ns1.google.com" : {
            "a" : [
               "216.239.32.10"
            ],
            "aaaa" : [
               "2001:4860:4802:32::a"
            ]
         },
         "ns4.google.com" : {
            "aaaa" : [
               "2001:4860:4802:38::a"
            ],
            "a" : [
               "216.239.38.10"
            ]
         }
      },
      "cname_paths" : {}
   }
}
```

## TODO

- Productionise the app
- Add comments for godocs
- Add defer and recover 
- Rewrite the resolvers package so the tool downloads resolvers from https://public-dns.info/nameservers-all.csv
- Validate resolvers with a simple dns lookup to check they don't return invalid responses
- Add settings to the configutation file