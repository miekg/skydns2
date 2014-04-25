// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	nameserver string
	rtimeout   time.Duration
	wtimeout   time.Duration
	ldns       string
	etcdclient string
	domain     string
	dnssec     string
	roundrobin bool
)

func init() {
	flag.StringVar(&domain, "domain",
		func() string {
			if x := os.Getenv("SKYDNS_DOMAIN"); x != "" {
				return x
			}
			return "skydns.local"
		}(), "domain to anchor requests to or env. var. SKYDNS_DOMAIN")
	flag.StringVar(&ldns, "dns",
		func() string {
			if x := os.Getenv("SKYDNS_DNS"); x != "" {
				return x
			}
			return "127.0.0.1:53"
		}(), "ip:port to bind to for DNS or env. var SKYDNS_DNS")
	flag.StringVar(&etcdclient, "etcd", "", "url of etcd")
	flag.DurationVar(&rtimeout, "rtimeout", 2*time.Second, "read timeout")
	flag.DurationVar(&wtimeout, "wtimeout", 2*time.Second, "write timeout")
	flag.StringVar(&nameserver, "nameserver", "", "nameserver address to forward (non-local) queries to e.g. 8.8.8.8:53,8.8.4.4:53")
	flag.StringVar(&dnssec, "dnssec", "", "basename of DNSSEC key file e.q. Kskydns.local.+005+38250")
	flag.BoolVar(&roundrobin, "roundrobin", true, "round robin A/AAAA replies")
}

func main() {
	flag.Parse()
	nameservers := strings.Split(nameserver, ",")
	if len(nameservers) == 1 && nameservers[0] == "" {
		nameservers = make([]string, 0)
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range config.Servers {
			nameservers = append(nameservers, net.JoinHostPort(s, config.Port))
		}
	}

	s := NewServer(domain, ldns, nameservers, etcdclient)
	s.ReadTimeout = rtimeout
	s.WriteTimeout = wtimeout
	s.RoundRobin = roundrobin

	if dnssec != "" {
		k, p, e := ParseKeyFile(dnssec)
		if e != nil {
			log.Fatal(e)
		}
		if k.Header().Name != dns.Fqdn(domain) {
			log.Fatal(errors.New("ownername of DNSKEY must match SkyDNS domain"))
		}
		s.SetKeys(k, p)
	}

	waiter, err := s.Start()
	if err != nil {
		log.Fatal(err)
	}
	waiter.Wait()
}
