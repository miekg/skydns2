// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

// etcd needs to be running on http://127.0.0.1:4001

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/coreos/go-etcd/etcd"
	"github.com/miekg/dns"
)

// Keep global port counter that increments with 10 for each
// new call to newTestServer. The dns server is started on port 'Port'.
var Port = 9400
var StrPort = "9400" // string equivalent of Port

func addService(t *testing.T, s *server, k string, ttl uint64, m *Service) {
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := Path(k)
	_, err = s.client.Create(path, string(b), ttl)
	if err != nil {
		// TODO(miek): allow for existing keys...
		t.Fatal(err)
	}
}

func delService(t *testing.T, s *server, k string) {
	path, _ := Path(k)
	_, err := s.client.Delete(path, false)
	if err != nil {
		t.Fatal(err)
	}
}

func newTestServer(t *testing.T) *server {
	Port += 10
	StrPort = strconv.Itoa(Port)
	s := new(server)
	client := etcd.NewClient([]string{"http://127.0.0.1:4001"})
	client.SyncCluster()

	s.group = new(sync.WaitGroup)
	s.client = client
	s.config = new(Config)
	s.config.DnsAddr = "127.0.0.1:" + StrPort
	s.config.Nameservers = []string{"8.8.4.4:53"}
	s.config.Domain = "skydns.test."
	// some defaults copied over from config.go
	s.config.Priority = 10
	s.config.Ttl = 3600
	go s.Run()
	return s
}

func TestDNSForward(t *testing.T) {
	s := newTestServer(t)
	defer s.Stop()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, "localhost:"+StrPort)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 || resp.Rcode != dns.RcodeSuccess {
		t.Fatal("Answer expected to have A records or rcode not equal to RcodeSuccess")
	}
	// TCP
	c.Net = "tcp"
	resp, _, err = c.Exchange(m, "localhost:"+StrPort)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 || resp.Rcode != dns.RcodeSuccess {
		t.Fatal("Answer expected to have A records or rcode not equal to RcodeSuccess")
	}
}

func TestDNS(t *testing.T) {
	s := newTestServer(t)
	defer s.Stop()

	for _, serv := range services {
		m := &Service{Host: serv.Host, Port: serv.Port}
		addService(t, s, serv.key, 0, m)
		defer delService(t, s, serv.key)
	}
	c := new(dns.Client)
	for _, tc := range dnsTestCases {
		m := new(dns.Msg)
		m.SetQuestion(tc.Qname, tc.Qtype)
		resp, _, err := c.Exchange(m, "127.0.0.1:"+StrPort)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != len(tc.Answer) {
			t.Fatalf("Response for %q contained %d results, %d expected", tc.Qname, len(resp.Answer), len(tc.Answer))
		}
		for i, a := range resp.Answer {
			if a.Header().Name != tc.Answer[i].Header().Name {
				t.Errorf("Answer %d should have a Header Name of %q, but has %q", i, tc.Answer[i].Header().Name, a.Header().Name)
			}
			if a.Header().Ttl != tc.Answer[i].Header().Ttl {
				t.Errorf("Answer %d should have a Header TTL of %d, but has %d", i, tc.Answer[i].Header().Ttl, a.Header().Ttl)
			}
			if a.Header().Rrtype != tc.Answer[i].Header().Rrtype {
				t.Errorf("Answer %d should have a Header Response Type of %d, but has %d", i, tc.Answer[i].Header().Rrtype, a.Header().Rrtype)
			}

			switch x := a.(type) {
			case *dns.SRV:
				if x.Priority != tc.Answer[i].(*dns.SRV).Priority {
					t.Errorf("Answer %d should have a Priority of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Priority, x.Priority)
				}
				if x.Weight != tc.Answer[i].(*dns.SRV).Weight {
					t.Errorf("Answer %d should have a Weight of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Weight, x.Weight)
				}
				if x.Port != tc.Answer[i].(*dns.SRV).Port {
					t.Errorf("Answer %d should have a Port of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Port, x.Port)
				}
				if x.Target != tc.Answer[i].(*dns.SRV).Target {
					t.Errorf("Answer %d should have a Target of %q, but has %q", i, tc.Answer[i].(*dns.SRV).Target, x.Target)
				}
			case *dns.A:
				if x.A.String() != tc.Answer[i].(*dns.A).A.String() {
					t.Errorf("Answer %d should have a Address of %q, but has %q", i, tc.Answer[i].(*dns.A).A.String(), x.A.String())
				}
			case *dns.AAAA:
				if x.AAAA.String() != tc.Answer[i].(*dns.AAAA).AAAA.String() {
					t.Errorf("Answer %d should have a Address of %q, but has %q", i, tc.Answer[i].(*dns.AAAA).AAAA.String(), x.AAAA.String())
				}
			}
		}
		for i, e := range resp.Extra {
			switch x := e.(type) {
			case *dns.A:
				if x.A.String() != tc.Extra[i].(*dns.A).A.String() {
					t.Errorf("Extra %d should have a Address of %q, but has %q", i, tc.Extra[i].(*dns.A).A.String(), x.A.String())
				}
			case *dns.AAAA:
				if x.AAAA.String() != tc.Extra[i].(*dns.AAAA).AAAA.String() {
					t.Errorf("Extra %d should have a Address of %q, but has %q", i, tc.Extra[i].(*dns.AAAA).AAAA.String(), x.AAAA.String())
				}
			}

		}
	}
}

var services = []*Service{
	{Host: "server2", Port: 8080, key: "100.server1.development.region1.skydns.test."},
	{Host: "server2", Port: 80, key: "101.server2.production.region1.skydns.test."},
	{Host: "server5", key: "102.server3.production.region2.skydns.test."},
	{Host: "server6", key: "103.server4.development.region1.skydns.test."},
	{Host: "10.0.0.1", key: "104.server1.development.region1.skydns.test."},
	{Host: "2001::8:8:8:8", key: "105.server3.production.region2.skydns.test."},
}

type dnsTestCase struct {
	Qname  string
	Qtype  uint16
	Answer []dns.RR
	Extra  []dns.RR
}

var dnsTestCases = []dnsTestCase{
	// Full Name Test
	{
		Qname: "100.server1.development.region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("100.server1.development.region1.skydns.test. 3600 SRV 10 0 8080 server.")},
	},
	// A Record Test
	{
		Qname: "104.server1.development.region1.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1")},
	},
	// AAAAA Record Test
	{
		Qname: "105.server1.development.region1.skydns.test.", Qtype: dns.TypeAAAA,
		Answer: []dns.RR{newAAAA("105.server1.development.region1.skydns.test. 3600 AAAA 2001::8:8:8:8")},
	},
	// Region Priority Test
	{
		Qname: "region1.*.testservice.production.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("region1.*.testservice.production.skydns.test. 30 SRV 10 100 9001 server2")},
	},
}

/*
func newTestServerDNSSEC(leader, secret, nameserver string) *Server {
	s := newTestServer(leader, secret, nameserver)
	key, _ := dns.NewRR("skydns.local. IN DNSKEY 256 3 5 AwEAAaXfO+DOBMJsQ5H4TfiabwSpqE4cGL0Qlvh5hrQumrjr9eNSdIOjIHJJKCe56qBU5mH+iBlXP29SVf6UiiMjIrAPDVhClLeWFe0PC+XlWseAyRgiLHdQ8r95+AfkhO5aZgnCwYf9FGGSaT0+CRYN+PyDbXBTLK5FN+j5b6bb7z+d")
	s.dnsKey = key.(*dns.DNSKEY)
	s.keyTag = s.dnsKey.KeyTag()
	s.privKey, _ = s.dnsKey.ReadPrivateKey(strings.NewReader(`
Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: pd874M4EwmxDkfhN+JpvBKmoThwYvRCW+HmGtC6auOv141J0g6MgckkoJ7nqoFTmYf6IGVc/b1JV/pSKIyMisA8NWEKUt5YV7Q8L5eVax4DJGCIsd1Dyv3n4B+SE7lpmCcLBh/0UYZJpPT4JFg34/INtcFMsrkU36PlvptvvP50=
PublicExponent: AQAB
PrivateExponent: C6e08GXphbPPx6j36ZkIZf552gs1XcuVoB4B7hU8P/Qske2QTFOhCwbC8I+qwdtVWNtmuskbpvnVGw9a6X8lh7Z09RIgzO/pI1qau7kyZcuObDOjPw42exmjqISFPIlS1wKA8tw+yVzvZ19vwRk1q6Rne+C1romaUOTkpA6UXsE=
Prime1: 2mgJ0yr+9vz85abrWBWnB8Gfa1jOw/ccEg8ZToM9GLWI34Qoa0D8Dxm8VJjr1tixXY5zHoWEqRXciTtY3omQDQ==
Prime2: wmxLpp9rTzU4OREEVwF43b/TxSUBlUq6W83n2XP8YrCm1nS480w4HCUuXfON1ncGYHUuq+v4rF+6UVI3PZT50Q==
Exponent1: wkdTngUcIiau67YMmSFBoFOq9Lldy9HvpVzK/R0e5vDsnS8ZKTb4QJJ7BaG2ADpno7pISvkoJaRttaEWD3a8rQ==
Exponent2: YrC8OglEXIGkV3tm2494vf9ozPL6+cBkFsPPg9dXbvVCyyuW0pGHDeplvfUqs4nZp87z8PsoUL+LAUqdldnwcQ==
Coefficient: mMFr4+rDY5V24HZU3Oa5NEb55iQ56ZNa182GnNhWqX7UqWjcUUGjnkCy40BqeFAQ7lp52xKHvP5Zon56mwuQRw==
Created: 20140126132645
Publish: 20140126132645
Activate: 20140126132645`), "stdin")
	return s
}
*/

/*

func TestDNSARecords(t *testing.T) {
	s := newTestServer("", "", "")
	defer s.Stop()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("skydns.test.", dns.TypeA)
	resp, _, err := c.Exchange(m, "localhost:"+StrPort)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatal("Answer expected to have 2 A records but has", len(resp.Answer))
	}
}

// DNSSEC tests

func sectionCheck(t *testing.T, resp []dns.RR, tc []dns.RR) {
	// check the RRs in the response
	for i, r := range resp {
		if r.Header().Name != tc[i].Header().Name {
			t.Errorf("Response should have a Header Name of %q, but has %q", r.Header().Name, tc[i].Header().Name)
		}
		if r.Header().Rrtype != tc[i].Header().Rrtype {
			t.Errorf("Response should have a Header Type of %q, but has %q", r.Header().Rrtype, tc[i].Header().Rrtype)
		}
		if r.Header().Ttl != tc[i].Header().Ttl {
			t.Errorf("Response should have a Header Ttl of %q, but has %q", r.Header().Ttl, tc[i].Header().Ttl)
		}
		switch rt := r.(type) {
		case *dns.DNSKEY:
			tt := tc[i].(*dns.DNSKEY)
			if rt.Flags != tt.Flags {
				t.Errorf("DNSKEY flags should be %q, but is %q", rt.Flags, tt.Flags)
			}
			if rt.Protocol != tt.Protocol {
				t.Errorf("DNSKEY protocol should be %q, but is %q", rt.Protocol, tt.Protocol)
			}
			if rt.Algorithm != tt.Algorithm {
				t.Errorf("DNSKEY algorithm should be %q, but is %q", rt.Algorithm, tt.Algorithm)
			}
		case *dns.RRSIG:
			tt := tc[i].(*dns.RRSIG)
			if rt.TypeCovered != tt.TypeCovered {
				t.Errorf("RRSIG type-covered should be %q, but is %q", rt.TypeCovered, tt.TypeCovered)
			}
			if rt.Algorithm != tt.Algorithm {
				t.Errorf("RRSIG algorithm should be %q, but is %q", rt.Algorithm, tt.Algorithm)
			}
			if rt.Labels != tt.Labels {
				t.Errorf("RRSIG label should be %q, but is %q", rt.Labels, tt.Labels)
			}
			if rt.OrigTtl != tt.OrigTtl {
				t.Errorf("RRSIG orig-ttl should be %q, but is %q", rt.OrigTtl, tt.OrigTtl)
			}
			if rt.KeyTag != tt.KeyTag {
				t.Errorf("RRSIG key-tag should be %q, but is %q", rt.KeyTag, tt.KeyTag)
			}
			if rt.SignerName != tt.SignerName {
				t.Errorf("RRSIG signer-name should be %q, but is %q", rt.SignerName, tt.SignerName)
			}
		}
	}
}

func TestDNSSEC(t *testing.T) {
	s := newTestServer("", "", "")
	defer s.Stop()

	for _, m := range services {
		s.registry.Add(m)
	}
	c := new(dns.Client)
	for _, tc := range dnssecTestCases {
		m := newMsg(tc)
		resp, _, err := c.Exchange(m, "localhost:"+StrPort)
		if err != nil {
			t.Fatal(err)
		}
		sectionCheck(t, resp.Answer, tc.Answer)
	}
}

type dnssecTestCase struct {
	Question dns.Question
	Answer   []dns.RR
	Ns       []dns.RR
	Extra    []dns.RR
}

var dnssecTestCases = []dnssecTestCase{
	// DNSKEY Test
	{
		Question: dns.Question{"skydns.test.", dns.TypeDNSKEY, dns.ClassINET},
		Answer: []dns.RR{&dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   "skydns.test.",
				Ttl:    origTTL,
				Rrtype: dns.TypeDNSKEY,
			},
			Flags:     256,
			Protocol:  3,
			Algorithm: 5,
			PublicKey: "not important",
		},
			&dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   "skydns.test.",
					Ttl:    origTTL,
					Rrtype: dns.TypeRRSIG,
				},
				TypeCovered: dns.TypeDNSKEY,
				Algorithm:   5,
				Labels:      2,
				OrigTtl:     origTTL,
				Expiration:  0,
				Inception:   0,
				KeyTag:      51945,
				SignerName:  "skydns.test.",
				Signature:   "not important",
			},
		},
	},
}

// newMsg return a new dns.Msg set with DNSSEC and with the question from the tc.
func newMsg(tc dnssecTestCase) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(tc.Question.Name, tc.Question.Qtype)
	m.SetEdns0(4096, true)
	return m
}
*/

func newA(rr string) *dns.A       { r, _ := dns.NewRR(rr); return r.(*dns.A) }
func newAAAA(rr string) *dns.AAAA { r, _ := dns.NewRR(rr); return r.(*dns.AAAA) }
func newSRV(rr string) *dns.SRV   { r, _ := dns.NewRR(rr); return r.(*dns.SRV) }
