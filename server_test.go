// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

// etcd needs to be running on http://127.0.0.1:4001

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/coreos/go-log/log"
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
	t.Logf("Adding path %s:", path)
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
	s.config.Hostmaster = "hostmaster.skydns.test."
	s.config.DomainLabels = 2
	s.config.Priority = 10
	s.config.Ttl = 3600
	s.config.log = log.New("skydns", false, log.NullSink())
	go s.Run()
	return s
}

func newTestServerDNSSEC(t *testing.T) *server {
	var err error
	s := newTestServer(t)
	s.config.PubKey = newDNSKEY("skydns.test. IN DNSKEY 256 3 5 AwEAAaXfO+DOBMJsQ5H4TfiabwSpqE4cGL0Qlvh5hrQumrjr9eNSdIOjIHJJKCe56qBU5mH+iBlXP29SVf6UiiMjIrAPDVhClLeWFe0PC+XlWseAyRgiLHdQ8r95+AfkhO5aZgnCwYf9FGGSaT0+CRYN+PyDbXBTLK5FN+j5b6bb7z+d")
	s.config.KeyTag = s.config.PubKey.KeyTag()
	s.config.PrivKey, err = s.config.PubKey.ReadPrivateKey(strings.NewReader(`Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: pd874M4EwmxDkfhN+JpvBKmoThwYvRCW+HmGtC6auOv141J0g6MgckkoJ7nqoFTmYf6IGVc/b1JV/pSKIyMisA8NWEKUt5YV7Q8L5eVax4DJGCIsd1Dyv3n4B+SE7lpmCcLBh/0UYZJpPT4JFg34/INtcFMsrkU36PlvptvvP50=
PublicExponent: AQAB
PrivateExponent: C6e08GXphbPPx6j36ZkIZf552gs1XcuVoB4B7hU8P/Qske2QTFOhCwbC8I+qwdtVWNtmuskbpvnVGw9a6X8lh7Z09RIgzO/pI1qau7kyZcuObDOjPw42exmjqISFPIlS1wKA8tw+yVzvZ19vwRk1q6Rne+C1romaUOTkpA6UXsE=
Prime1: 2mgJ0yr+9vz85abrWBWnB8Gfa1jOw/ccEg8ZToM9GLWI34Qoa0D8Dxm8VJjr1tixXY5zHoWEqRXciTtY3omQDQ==
Prime2: wmxLpp9rTzU4OREEVwF43b/TxSUBlUq6W83n2XP8YrCm1nS480w4HCUuXfON1ncGYHUuq+v4rF+6UVI3PZT50Q==
Exponent1: wkdTngUcIiau67YMmSFBoFOq9Lldy9HvpVzK/R0e5vDsnS8ZKTb4QJJ7BaG2ADpno7pISvkoJaRttaEWD3a8rQ==
Exponent2: YrC8OglEXIGkV3tm2494vf9ozPL6+cBkFsPPg9dXbvVCyyuW0pGHDeplvfUqs4nZp87z8PsoUL+LAUqdldnwcQ==
Coefficient: mMFr4+rDY5V24HZU3Oa5NEb55iQ56ZNa182GnNhWqX7UqWjcUUGjnkCy40BqeFAQ7lp52xKHvP5Zon56mwuQRw==
`), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDNSExpire(t *testing.T) {
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	serv := services[0]
	addService(t, s, serv.key, 1, serv)
	// defer delService(t, s, serv.key) // It will delete itself...magically

	c := new(dns.Client)
	tc := dnsTestCases[0]
	m := new(dns.Msg)
	m.SetQuestion(tc.Qname, tc.Qtype)
	if tc.dnssec == true {
		m.SetEdns0(4096, true)
	}
	resp, _, err := c.Exchange(m, "127.0.0.1:"+StrPort)
	if err != nil {
		t.Fatalf("failing: %s: %s\n", m.String(), err.Error())
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Logf("%v\n", resp)
		t.Fail()
	}
	// Sleep to let it expire.
	time.Sleep(2 * time.Second)
	resp, _, err = c.Exchange(m, "127.0.0.1:"+StrPort)
	if err != nil {
		t.Errorf("failing: %s\n", err.Error())
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Logf("%v\n", resp)
		t.Fail()
	}
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
func TestDNSTtlRRset(t *testing.T) {
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	ttl := uint32(60)
	for _, serv := range services {
		addService(t, s, serv.key, uint64(ttl), serv)
		defer delService(t, s, serv.key)
		ttl += 60
	}
	c := new(dns.Client)
	tc := dnsTestCases[10]
	m := new(dns.Msg)
	m.SetQuestion(tc.Qname, tc.Qtype)
	if tc.dnssec == true {
		m.SetEdns0(4096, true)
	}
	resp, _, err := c.Exchange(m, "127.0.0.1:"+StrPort)
	if err != nil {
		t.Fatalf("failing: %s: %s\n", m.String(), err.Error())
	}
	t.Logf("%s\n", resp)
	ttl = 60
	for i, a := range resp.Answer {
		if a.Header().Ttl != ttl {
			t.Errorf("Answer %d should have a Header TTL of %d, but has %d", i, ttl, a.Header().Ttl)
		}
	}
}

func TestDNS(t *testing.T) {
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	for _, serv := range services {
		addService(t, s, serv.key, 0, serv)
		defer delService(t, s, serv.key)
	}
	c := new(dns.Client)
	for _, tc := range dnsTestCases {
		m := new(dns.Msg)
		m.SetQuestion(tc.Qname, tc.Qtype)
		if tc.dnssec == true {
			m.SetEdns0(4096, true)
		}
		resp, _, err := c.Exchange(m, "127.0.0.1:"+StrPort)
		if err != nil {
			t.Fatalf("failing: %s: %s\n", m.String(), err.Error())
		}
		t.Logf("%s\n", resp)
		if len(resp.Answer) != len(tc.Answer) {
			t.Fatalf("response for %q contained %d results, %d expected", tc.Qname, len(resp.Answer), len(tc.Answer))
		}
		for i, a := range resp.Answer {
			if a.Header().Name != tc.Answer[i].Header().Name {
				t.Fatalf("answer %d should have a Header Name of %q, but has %q", i, tc.Answer[i].Header().Name, a.Header().Name)
			}
			if a.Header().Ttl != tc.Answer[i].Header().Ttl {
				t.Fatalf("Answer %d should have a Header TTL of %d, but has %d", i, tc.Answer[i].Header().Ttl, a.Header().Ttl)
			}
			if a.Header().Rrtype != tc.Answer[i].Header().Rrtype {
				t.Fatalf("answer %d should have a header response type of %d, but has %d", i, tc.Answer[i].Header().Rrtype, a.Header().Rrtype)
			}
			switch x := a.(type) {
			case *dns.SRV:
				if x.Priority != tc.Answer[i].(*dns.SRV).Priority {
					t.Fatalf("answer %d should have a Priority of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Priority, x.Priority)
				}
				if x.Weight != tc.Answer[i].(*dns.SRV).Weight {
					t.Fatalf("answer %d should have a Weight of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Weight, x.Weight)
				}
				if x.Port != tc.Answer[i].(*dns.SRV).Port {
					t.Fatalf("answer %d should have a Port of %d, but has %d", i, tc.Answer[i].(*dns.SRV).Port, x.Port)
				}
				if x.Target != tc.Answer[i].(*dns.SRV).Target {
					t.Fatalf("answer %d should have a Target of %q, but has %q", i, tc.Answer[i].(*dns.SRV).Target, x.Target)
				}
			case *dns.A:
				if x.A.String() != tc.Answer[i].(*dns.A).A.String() {
					t.Fatalf("answer %d should have a Address of %q, but has %q", i, tc.Answer[i].(*dns.A).A.String(), x.A.String())
				}
			case *dns.AAAA:
				if x.AAAA.String() != tc.Answer[i].(*dns.AAAA).AAAA.String() {
					t.Fatalf("answer %d should have a Address of %q, but has %q", i, tc.Answer[i].(*dns.AAAA).AAAA.String(), x.AAAA.String())
				}
			case *dns.DNSKEY:
				tt := tc.Answer[i].(*dns.DNSKEY)
				if x.Flags != tt.Flags {
					t.Fatalf("DNSKEY flags should be %q, but is %q", x.Flags, tt.Flags)
				}
				if x.Protocol != tt.Protocol {
					t.Fatalf("DNSKEY protocol should be %q, but is %q", x.Protocol, tt.Protocol)
				}
				if x.Algorithm != tt.Algorithm {
					t.Fatalf("DNSKEY algorithm should be %q, but is %q", x.Algorithm, tt.Algorithm)
				}
			case *dns.RRSIG:
				tt := tc.Answer[i].(*dns.RRSIG)
				if x.TypeCovered != tt.TypeCovered {
					t.Fatalf("RRSIG type-covered should be %d, but is %d", x.TypeCovered, tt.TypeCovered)
				}
				if x.Algorithm != tt.Algorithm {
					t.Fatalf("RRSIG algorithm should be %d, but is %d", x.Algorithm, tt.Algorithm)
				}
				if x.Labels != tt.Labels {
					t.Fatalf("RRSIG label should be %d, but is %d", x.Labels, tt.Labels)
				}
				if x.OrigTtl != tt.OrigTtl {
					t.Fatalf("RRSIG orig-ttl should be %d, but is %d", x.OrigTtl, tt.OrigTtl)
				}
				if x.KeyTag != tt.KeyTag {
					t.Fatalf("RRSIG key-tag should be %d, but is %d", x.KeyTag, tt.KeyTag)
				}
				if x.SignerName != tt.SignerName {
					t.Fatalf("RRSIG signer-name should be %q, but is %q", x.SignerName, tt.SignerName)
				}
			case *dns.SOA:
				tt := tc.Answer[i].(*dns.SOA)
				if x.Ns != tt.Ns {
					t.Fatalf("SOA nameserver should be %q, but is %q", x.Ns, tt.Ns)
				}
			case *dns.PTR:
				tt := tc.Answer[i].(*dns.PTR)
				if x.Ptr != tt.Ptr {
					t.Fatalf("PTR ptr should be %q, but is %q", x.Ptr, tt.Ptr)
				}
			}
			for i, n := range resp.Ns {
				switch x := n.(type) {
				case *dns.SOA:
					tt := tc.Answer[i].(*dns.SOA)
					if x.Ns != tt.Ns {
						t.Fatalf("SOA nameserver should be %q, but is %q", x.Ns, tt.Ns)
					}
				case *dns.NS:
					tt := tc.Answer[i].(*dns.NS)
					if x.Ns != tt.Ns {
						t.Fatalf("NS nameserver should be %q, but is %q", x.Ns, tt.Ns)
					}
				case *dns.NSEC3:
					// TODO(miek)
				}
			}
			for i, e := range resp.Extra {
				switch x := e.(type) {
				case *dns.A:
					if x.A.String() != tc.Extra[i].(*dns.A).A.String() {
						t.Fatalf("extra %d should have a address of %q, but has %q", i, tc.Extra[i].(*dns.A).A.String(), x.A.String())
					}
				case *dns.AAAA:
					if x.AAAA.String() != tc.Extra[i].(*dns.AAAA).AAAA.String() {
						t.Fatalf("extra %d should have a address of %q, but has %q", i, tc.Extra[i].(*dns.AAAA).AAAA.String(), x.AAAA.String())
					}
				}
			}
		}
	}
}

type dnsTestCase struct {
	Qname  string
	Qtype  uint16
	dnssec bool
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

var services = []*Service{
	{Host: "server1", Port: 8080, key: "100.server1.development.region1.skydns.test."},
	{Host: "server2", Port: 80, key: "101.server2.production.region1.skydns.test."},
	{Host: "server4", Port: 80, Priority: 333, key: "102.server4.development.region6.skydns.test."},
	{Host: "server3", key: "103.server4.development.region2.skydns.test."},
	{Host: "10.0.0.1", key: "104.server1.development.region1.skydns.test."},
	{Host: "2001::8:8:8:8", key: "105.server3.production.region2.skydns.test."},
	{Host: "104.server1.development.region1.skydns.test", key: "1.cname.skydns.test."},
	{Host: "100.server1.development.region1.skydns.test", key: "2.cname.skydns.test."},
	{Host: "4.cname.skydns.test", key: "3.cname.skydns.test."},
	{Host: "3.cname.skydns.test", key: "4.cname.skydns.test."},
	{Host: "10.0.0.2", key: "ttl.skydns.test.", Ttl: 360},
	{Host: "reverse.example.com", key: "1.0.0.10.in-addr.arpa."},	// 10.0.0.1
	{Host: "server1", Weight: 130, key: "100.server1.region5.skydns.test."},
	{Host: "server2", Weight: 80, key: "101.server2.region5.skydns.test."},
	{Host: "server3", Weight: 150, key: "103.server3.region5.skydns.test."},
	{Host: "server4", Priority: 30, key: "104.server4.region5.skydns.test."},
}

var dnsTestCases = []dnsTestCase{
	// Full Name Test
	{
		Qname: "100.server1.development.region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("100.server1.development.region1.skydns.test. 3600 SRV 10 100 8080 server1.")},
	},
	// SOA Record Test
	{
		Qname: "skydns.test.", Qtype: dns.TypeSOA,
		Answer: []dns.RR{newSOA("skydns.test. 3600 SOA ns1.dns.skydns.test. hostmaster.skydns.test. 0 0 0 0 0")},
	},
	// NS Record Test
	{
		Qname: "skydns.test.", Qtype: dns.TypeNS,
		Answer: []dns.RR{newNS("skydns.test. 3600 NS ns1.dns.skydns.test.")},
	},
	// A Record For NS Record Test
	{
		Qname: "ns1.dns.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{newA("ns1.dns.skydns.test. 3600 A 127.0.0.1")},
	},
	// A Record Test
	{
		Qname: "104.server1.development.region1.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1")},
	},
	// A Record Test with SRV
	{
		Qname: "104.server1.development.region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("104.server1.development.region1.skydns.test. 3600 SRV 10 100 0 104.server1.development.region1.skydns.test.")},
		Extra:  []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1")},
	},
	// AAAAA Record Test
	{
		Qname: "105.server3.production.region2.skydns.test.", Qtype: dns.TypeAAAA,
		Answer: []dns.RR{newAAAA("105.server3.production.region2.skydns.test. 3600 AAAA 2001::8:8:8:8")},
	},
	// TTL Test
	{
		Qname: "ttl.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{newA("ttl.skydns.test. 360 A 10.0.0.2")},
	},
	// CNAME Test
	{
		Qname: "1.cname.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			newCNAME("1.cname.skydns.test. 3600 CNAME 104.server1.development.region1.skydns.test."),
			newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1"),
		},
	},
	// Direct CNAME Test
	{
		Qname: "1.cname.skydns.test.", Qtype: dns.TypeCNAME,
		Answer: []dns.RR{
			newCNAME("1.cname.skydns.test. 3600 CNAME 104.server1.development.region1.skydns.test."),
		},
	},
	// CNAME (unresolvable)
	{
		Qname: "2.cname.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{},
	},
	// CNAME loop detection
	{
		Qname: "3.cname.skydns.test.", Qtype: dns.TypeA,
		Answer: []dns.RR{},
	},
	// Priority Test
	{
		Qname: "region6.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("region6.skydns.test. 3600 SRV 333 100 80 server4.")},
	},
	// Subdomain Test
	{
		Qname: "region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("region1.skydns.test. 3600 SRV 10 33 8080 server1."),
			newSRV("region1.skydns.test. 3600 SRV 10 33 0 104.server1.development.region1.skydns.test."),
			newSRV("region1.skydns.test. 3600 SRV 10 33 80 server2")},
		Extra: []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1")},
	},
	// Subdomain Weight Test
	{
		Qname: "region5.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("region5.skydns.test. 3600 SRV 10 36 0 server1."),
			newSRV("region5.skydns.test. 3600 SRV 10 22 0 server2."),
			newSRV("region5.skydns.test. 3600 SRV 10 41 0 server3."),
			newSRV("region5.skydns.test. 3600 SRV 30 100 0 server4.")},
	},
	// Wildcard Test
	{
		Qname: "*.region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("*.region1.skydns.test. 3600 SRV 10 33 8080 server1."),
			newSRV("*.region1.skydns.test. 3600 SRV 10 33 0 104.server1.development.region1.skydns.test."),
			newSRV("*.region1.skydns.test. 3600 SRV 10 33 80 server2")},
		Extra: []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1")},
	},
	// Wildcard Test
	{
		Qname: "production.*.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("production.*.skydns.test. 3600 IN SRV 10 50 80 server2."),
			newSRV("production.*.skydns.test. 3600 IN SRV 10 50 0 105.server3.production.region2.skydns.test.")},
		Extra: []dns.RR{newAAAA("105.server3.production.region2.skydns.test. 3600 IN AAAA 2001::8:8:8:8")},
	},
	// NXDOMAIN Test
	{
		Qname: "doesnotexist.skydns.test.", Qtype: dns.TypeA,
		Ns: []dns.RR{newSOA("skydns.test. 3600 SOA ns1.dns.skydns.test. hostmaster.skydns.test. 0 0 0 0 0")},
	},
	// NODATA Test
	{
		Qname: "104.server1.development.region1.skydns.test.", Qtype: dns.TypeTXT,
		Ns: []dns.RR{newSOA("skydns.test. 3600 SOA ns1.dns.skydns.test. hostmaster.skydns.test. 0 0 0 0 0")},
	},

	// DNSSEC

	// DNSKEY Test
	{
		dnssec: true,
		Qname:  "skydns.test.", Qtype: dns.TypeDNSKEY,
		Answer: []dns.RR{newDNSKEY("skydns.test. 3600 DNSKEY 256 3 5 deadbeaf"),
			newRRSIG("skydns.test. 3600 RRSIG DNSKEY 5 2 3600 0 0 51945 skydns.test. deadbeaf")},
	},
	// Signed Response Test
	{
		dnssec: true,
		Qname:  "104.server1.development.region1.skydns.test.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{newSRV("104.server1.development.region1.skydns.test. 3600 SRV 10 100 0 104.server1.development.region1.skydns.test."),
			newRRSIG("104.server1.development.region1.skydns.test. 3600 RRSIG SRV 5 6 3600 0 0 51945 skydns.test. deadbeaf")},
		Extra: []dns.RR{newA("104.server1.development.region1.skydns.test. 3600 A 10.0.0.1"),
			newRRSIG("104.server1.developmen.region1.skydns.test. 3600 RRSIG A 5 6 3600 0 0 51945 skydns.test. deadbeaf")},
	},
	// NXDOMAIN Test

	// NODATA Test

	// Wildcard Test

	// Reverse

	// Reverse v4 local answer
	{
		Qname: "1.0.0.10.in-addr.arpa.", Qtype: dns.TypePTR,
		Answer: []dns.RR{newPTR("1.0.0.10.in-addr.arpa. 3600 PTR reverse.example.com.")},
	},
	// Reverse v6 local answer
	// Reverse forwarding answer
	{
		Qname: "10.0.0.10.in-addr.arpa.", Qtype: dns.TypePTR,
		Ns: []dns.RR{newSOA("10.in-addr.arpa. 10800 SOA localhost. nobody.invalid. 1 0 0 0 0")},
	},
	// Reverse no answer
}

func newA(rr string) *dns.A           { r, _ := dns.NewRR(rr); return r.(*dns.A) }
func newAAAA(rr string) *dns.AAAA     { r, _ := dns.NewRR(rr); return r.(*dns.AAAA) }
func newCNAME(rr string) *dns.CNAME   { r, _ := dns.NewRR(rr); return r.(*dns.CNAME) }
func newSRV(rr string) *dns.SRV       { r, _ := dns.NewRR(rr); return r.(*dns.SRV) }
func newSOA(rr string) *dns.SOA       { r, _ := dns.NewRR(rr); return r.(*dns.SOA) }
func newNS(rr string) *dns.NS         { r, _ := dns.NewRR(rr); return r.(*dns.NS) }
func newDNSKEY(rr string) *dns.DNSKEY { r, _ := dns.NewRR(rr); return r.(*dns.DNSKEY) }
func newRRSIG(rr string) *dns.RRSIG   { r, _ := dns.NewRR(rr); return r.(*dns.RRSIG) }
func newNNSEC3(rr string) *dns.NSEC3  { r, _ := dns.NewRR(rr); return r.(*dns.NSEC3) }
func newPTR(rr string) *dns.PTR       { r, _ := dns.NewRR(rr); return r.(*dns.PTR) }

func BenchmarkDNSSingle(b *testing.B) {
	b.StopTimer()
	t := new(testing.T)
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	serv := services[0]
	addService(t, s, serv.key, 0, serv)
	defer delService(t, s, serv.key)

	c := new(dns.Client)
	tc := dnsTestCases[0]
	m := new(dns.Msg)
	m.SetQuestion(tc.Qname, tc.Qtype)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c.Exchange(m, "127.0.0.1:"+StrPort)
	}
}

func BenchmarkDNSWildcard(b *testing.B) {
	b.StopTimer()
	t := new(testing.T)
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	for _, serv := range services {
		m := &Service{Host: serv.Host, Port: serv.Port}
		addService(t, s, serv.key, 0, m)
		defer delService(t, s, serv.key)
	}

	c := new(dns.Client)
	tc := dnsTestCases[8] // Wildcard Test
	m := new(dns.Msg)
	m.SetQuestion(tc.Qname, tc.Qtype)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c.Exchange(m, "127.0.0.1:"+StrPort)
	}
}

func BenchmarkDNSSECSingle(b *testing.B) {
	b.StopTimer()
	t := new(testing.T)
	s := newTestServerDNSSEC(t)
	defer s.Stop()

	serv := services[0]
	addService(t, s, serv.key, 0, serv)
	defer delService(t, s, serv.key)

	c := new(dns.Client)
	tc := dnsTestCases[0]
	m := new(dns.Msg)
	m.SetQuestion(tc.Qname, tc.Qtype)
	m.SetEdns0(4096, true)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c.Exchange(m, "127.0.0.1:"+StrPort)
	}
}

// BenchmarkDNSSECError(b *testing.B) {}
