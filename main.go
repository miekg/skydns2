// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/miekg/dns"
)

var (
	tlskey     = ""
	tlspem     = ""
	config     = &Config{ReadTimeout: 0, Domain: "", DnsAddr: "", DNSSEC: ""}
	nameserver = ""
	machine    = ""
	discover   = false
	verbose    = false
)

const (
	SCacheCapacity = 10000
	RCacheCapacity = 100000
	RCacheTtl      = 60
)

func getEnv(key, def string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return def
}

func init() {
	flag.StringVar(&config.Domain, "domain", getEnv("SKYDNS_DOMAIN", "skydns.local."), "domain to anchor requests to (SKYDNS_DOMAIN)")
	flag.StringVar(&config.DnsAddr, "addr", getEnv("SKYDNS_ADDR", "127.0.0.1:53"), "ip:port to bind to (SKYDNS_ADDR)")
	flag.StringVar(&nameserver, "nameservers", getEnv("SKYDNS_NAMESERVERS", ""), "nameserver address(es) to forward (non-local) queries to e.g. 8.8.8.8:53,8.8.4.4:53")
	flag.StringVar(&machine, "machines", getEnv("ETCD_MACHINES", ""), "machine address(es) running etcd")
	flag.StringVar(&config.DNSSEC, "dnssec", "", "basename of DNSSEC key file e.q. Kskydns.local.+005+38250")
	flag.StringVar(&config.Local, "local", "", "optional unique value for this skydns instance")
	flag.StringVar(&tlskey, "tls-key", getEnv("ETCD_TLSKEY", ""), "TLS Private Key path")
	flag.StringVar(&tlspem, "tls-pem", getEnv("ETCD_TLSPEM", ""), "X509 Certificate")
	flag.DurationVar(&config.ReadTimeout, "rtimeout", 2*time.Second, "read timeout")
	flag.BoolVar(&config.RoundRobin, "round-robin", true, "round robin A/AAAA replies")
	flag.BoolVar(&discover, "discover", false, "discover new machines by watching /v2/_etcd/machines")
	flag.BoolVar(&verbose, "verbose", false, "log queries")

	// TTl
	// Minttl
	flag.StringVar(&config.Hostmaster, "hostmaster", "hostmaster@skydns.local.", "hostmaster email address to use")
	flag.IntVar(&config.SCache, "scache", SCacheCapacity, "capacity of the signature cache")
	flag.IntVar(&config.RCache, "rcache", 0, "capacity of the response cache") // default to 0 for now
	flag.IntVar(&config.RCacheTtl, "rcache-ttl", RCacheTtl, "TTL of the response cache")
}

func main() {
	flag.Parse()
	machines := strings.Split(machine, ",")
	client := NewClient(machines)
	if nameserver != "" {
		config.Nameservers = strings.Split(nameserver, ",")
	}
	config, err := loadConfig(client, config)
	if err != nil {
		log.Fatal(err)
	}
	s := NewServer(config, client)
	if s.config.Local != "" {
		s.config.Local = dns.Fqdn(s.config.Local)
	}

	if discover {
		go func() {
			recv := make(chan *etcd.Response)
			go s.client.Watch("/_etcd/machines/", 0, true, recv, nil)
			for {
				select {
				case n := <-recv:
					// we can see an n == nil, probably when we can't connect to etcd.
					if n != nil {
						s.UpdateClient(n)
					}
				}
			}
		}()
	}

	statsCollect()

	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}
