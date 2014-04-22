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
	dns        string
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
		}(), "Domain to anchor requests to or env. var. SKYDNS_DOMAIN")
	flag.StringVar(&ldns, "dns",
		func() string {
			if x := os.Getenv("SKYDNS_DNS"); x != "" {
				return x
			}
			return "127.0.0.1:53"
		}(), "IP:Port to bind to for DNS or env. var SKYDNS_DNS")
	flag.StringVar(&nameserver, "nameserver", "", "Nameserver address to forward (non-local) queries to e.g. 8.8.8.8:53,8.8.4.4:53")
	flag.StringVar(&dnssec, "dnssec", "", "Basename of DNSSEC key file e.q. Kskydns.local.+005+38250")
	flag.BoolVar(&roundrobin, "roundrobin", true, "Round robin A/AAAA replies")
}

func main() {
	flag.Parse()
	nameservers := strings.Split(nameserver, ",")
	// empty argument given
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

	s := server.NewServer(members, domain, ldns, lhttp, dataDir, rtimeout, wtimeout, secret, nameservers, !norr, tlskey, tlspem)

	if dnssec != "" {
		k, p, e := server.ParseKeyFile(dnssec)
		if e != nil {
			log.Fatal(e)
		}
		if k.Header().Name != dns.Fqdn(domain) {
			log.Fatal(errors.New("Owner name of DNSKEY must match SkyDNS domain"))
		}
		s.SetKeys(k, p)
	}

	waiter, err := s.Start()
	if err != nil {
		log.Fatal(err)
	}
	waiter.Wait()
}
