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
)

var (
	machines    = strings.Split(os.Getenv("ETCD_MACHINES"), ",")      // list of URLs to etcd
	nameservers = strings.Split(os.Getenv("SKYDNS_NAMESERVERS"), ",") // list of nameservers
	tlskey      = os.Getenv("ETCD_TLSKEY")                            // TLS private key path
	tlspem      = os.Getenv("ETCD_TLSPEM")                            // X509 certificate
	config      = &Config{ReadTimeout: 0, Domain: "", DnsAddr: "", DNSSEC: ""}
	nameserver  = ""
	machine     = ""
)

func init() {
	flag.StringVar(&config.Domain, "domain",
		func() string {
			if x := os.Getenv("SKYDNS_DOMAIN"); x != "" {
				return x
			}
			return "skydns.local."
		}(), "domain to anchor requests to (SKYDNS_DOMAIN)")
	flag.StringVar(&config.DnsAddr, "addr",
		func() string {
			if x := os.Getenv("SKYDNS_ADDR"); x != "" {
				return x
			}
			return "127.0.0.1:53"
		}(), "ip:port to bind to (SKYDNS_ADDR)")

	flag.StringVar(&nameserver, "nameserver", "", "nameserver address(es) to forward (non-local) queries to e.g. 8.8.8.8:53,8.8.4.4:53")
	flag.StringVar(&machine, "machines", "", "machine address(es) running etcd")
	flag.StringVar(&config.DNSSEC, "dnssec", "", "basename of DNSSEC key file e.q. Kskydns.local.+005+38250")
	flag.StringVar(&tlskey, "tls-key", "", "TLS Private Key path")
	flag.StringVar(&tlspem, "tls-pem", "", "X509 Certificate")
	flag.DurationVar(&config.ReadTimeout, "rtimeout", 2*time.Second, "read timeout")
	flag.BoolVar(&config.RoundRobin, "round-robin", true, "round robin A/AAAA replies")
	// TTl
	// Minttl
	flag.StringVar(&config.Hostmaster, "hostmaster", "hostmaster@skydns.local.", "hostmaster email address to use")
}

func newClient() (client *etcd.Client) {
	// set default if not specified in env
	if len(machines) == 1 && machines[0] == "" {
		machines[0] = "http://127.0.0.1:4001"

	}
	// override if we have a commandline flag as well
	if machine != "" {
		machines = strings.Split(machine, ",")	
	}
	if strings.HasPrefix(machines[0], "https://") {
		var err error
		if client, err = etcd.NewTLSClient(machines, tlspem, tlskey, ""); err != nil {
			log.Fatal(err)
		}
	} else {
		client = etcd.NewClient(machines)
	}
	client.SyncCluster()
	return client
}

func main() {
	flag.Parse()
	client := newClient()
	if nameserver != "" {
		config.Nameservers = strings.Split(nameserver, ",")
	}
	config, err := loadConfig(client, config)
	if err != nil {
		log.Fatal(err)
	}
	s := NewServer(config, client)

	statsCollect()

	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}
