// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"github.com/miekg/dns"
	"net"
	"path"
	"strings"
)

// This *is* the rdata from a SRV record, but with a twist.
// Host (Target in SRV) must be a domain name, but if it looks like an IP
// address (4/6), we will treat it like an IP address.
type Service struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Priority int    `json:"priority,omitempty"`

	ttl uint32
	key string
}

// NewSRV returns a new SRV record based on the Service.
func (s *Service) NewSRV(name string, ttl uint32, weight uint16) *dns.SRV {
	srv := &dns.SRV{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
		Priority: uint16(s.Priority), Weight: weight, Port: uint16(s.Port), Target: dns.Fqdn(s.Host)}
	return srv
}

func (s *Service) NewA(name string, ttl uint32, ip net.IP) *dns.A {
	a := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip}
	return a
}

func (s *Service) NewAAAA() *dns.AAAA {
	return nil
}

// path converts a domainname to an etcd path. If s looks like service.staging.skydns.local.,
// the resulting key will be /skydns/local/skydns/staging/service .
func Path(s string) string {
	l := dns.SplitDomainName(s)
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return path.Join(append([]string{"/skydns/"}, l...)...)
}

// domain is the opposite of path.
func Domain(s string) string {
	l := strings.Split(s, "/")
	// start with 1, to strip /skydns
	for i, j := 1, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return dns.Fqdn(strings.Join(l[1:len(l)-1], "."))
}
