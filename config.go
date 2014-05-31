// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/coreos/go-log/log"
	"github.com/miekg/dns"
)

// Config provides options to the SkyDNS resolver.
type Config struct {
	// The ip:port SkyDNS should be listening on for incoming DNS requests.
	DnsAddr string `json:"dns_addr,omitempty"`
	// The domain SkyDNS is authoritative for, defaults to skydns.local.
	Domain string `json:"domain,omitempty"`
	// The hostmaster responsible for this domain, defaults to hostmaster.<Domain>.
	Hostmaster string `json:"hostmaster,omitempty"`
	DNSSEC     string `json:"dnssec,omitempty"`
	// Round robin A/AAAA replies. Default is true.
	RoundRobin bool `json:"round_robin,omitempty"`
	// List of ip:port, seperated by commas of recursive nameservers to forward queries to.
	Nameservers []string      `json:"nameservers,omitempty"`
	ReadTimeout time.Duration `json:"read_timeout,omitempty"`
	// Default priority on SRV records when none is given. Defaults to 10.
	Priority uint16 `json:"priority"`
	// Default TTL, in seconds, when none is given in etcd. Defaults to 3600.
	Ttl uint32 `json:"ttl,omitempty"`
	// Minimum TTL, in seconds, for NXDOMAIN responses. Defaults to 300.
	MinTtl uint32 `json:"min_ttl,omitempty"`

	// DNSSEC key material
	PubKey          *dns.DNSKEY    `json:"-"`
	KeyTag          uint16         `json:"-"`
	PrivKey         dns.PrivateKey `json:"-"`
	DomainLabels    int            `json:"-"`
	ClosestEncloser *dns.NSEC3     `json:"-"`
	DenyWildcard    *dns.NSEC3     `json:"-"`

	log *log.Logger `json:"-"`
}

func LoadConfig(client *etcd.Client, config *Config) (*Config, error) {
	config.log = log.New("skydns", false,
		log.CombinedSink(os.Stderr, "[%s] %s %-9s | %s\n", []string{"prefix", "time", "priority", "message"}))

	// Override wat isn't set yet from the command line.
	n, err := client.Get("/skydns/config", false, false)
	if err != nil {
		config.log.Info("falling back to default configuration, could not read from etcd:", err)
		if err := setDefaults(config); err != nil {
			return nil, err
		}
		return config, nil
	}
	if err := json.Unmarshal([]byte(n.Node.Value), &config); err != nil {
		return nil, err
	}
	if err := setDefaults(config); err != nil {
		return nil, err
	}
	return config, nil
}

func setDefaults(config *Config) error {
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 2 * time.Second
	}
	if config.DnsAddr == "" {
		config.DnsAddr = "127.0.0.1:53"
	}
	if config.Domain == "" {
		config.Domain = "skydns.local."
	}
	if config.Hostmaster == "" {
		config.Hostmaster = "hostmaster." + config.Domain
	}
	// People probably don't know that SOA's email addresses cannot
	// contain @-signs, replace them with dots
	config.Hostmaster = dns.Fqdn(strings.Replace(config.Hostmaster, "@", ".", -1))
	if config.MinTtl == 0 {
		config.MinTtl = 60
	}
	if config.Ttl == 0 {
		config.Ttl = 3600
	}
	if config.Priority == 0 {
		config.Priority = 10
	}

	if len(config.Nameservers) == 0 {
		c, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		for _, s := range c.Servers {
			config.Nameservers = append(config.Nameservers, net.JoinHostPort(s, c.Port))
		}
	}
	config.Domain = dns.Fqdn(strings.ToLower(config.Domain))
	config.DomainLabels = dns.CountLabel(config.Domain)
	if config.DNSSEC != "" {
		// For some reason the + are replaces by spaces in etcd. Re-replace them
		keyfile := strings.Replace(config.DNSSEC, " ", "+", -1)
		k, p, err := ParseKeyFile(keyfile)
		if err != nil {
			return err
		}
		if k.Header().Name != dns.Fqdn(config.Domain) {
			return fmt.Errorf("ownername of DNSKEY must match SkyDNS domain")
		}
		k.Header().Ttl = config.Ttl
		config.PubKey = k
		config.KeyTag = k.KeyTag()
		config.PrivKey = p
		config.ClosestEncloser, config.DenyWildcard = newNSEC3CEandWildcard(config.Domain, config.Domain, config.MinTtl)
	}
	return nil
}
