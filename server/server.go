// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/coreos/go-systemd/activation"
	"github.com/miekg/dns"
	"github.com/skynetservices/skydns/cache"
	"github.com/skynetservices/skydns/msg"
)

const Version = "2.1.0a"

type server struct {
	backend Backend
	config  *Config

	group        *sync.WaitGroup
	dnsUDPclient *dns.Client // used for forwarding queries
	dnsTCPclient *dns.Client // used for forwarding queries
	scache       *cache.Cache
	rcache       *cache.Cache
}

type Backend interface {
	Records(name string, exact bool) ([]msg.Service, error)
	ReverseRecord(name string) (*msg.Service, error)
}

// FirstBackend exposes the Backend interface over multiple Backends, returning
// the first Backend that answers the provided record request. If no Backend answers
// a record request, the last error seen will be returned.
type FirstBackend []Backend

// FirstBackend implements Backend
var _ Backend = FirstBackend{}

func (g FirstBackend) Records(name string, exact bool) (records []msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if records, err = backend.Records(name, exact); err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

func (g FirstBackend) ReverseRecord(name string) (record *msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if record, err = backend.ReverseRecord(name); err == nil && record != nil {
			return record, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

// New returns a new SkyDNS server.
func New(backend Backend, config *Config) *server {
	return &server{
		backend: backend,
		config:  config,

		group:        new(sync.WaitGroup),
		scache:       cache.New(config.SCache, 0),
		rcache:       cache.New(config.RCache, config.RCacheTtl),
		dnsUDPclient: &dns.Client{Net: "udp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
		dnsTCPclient: &dns.Client{Net: "tcp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
	}
}

// Run is a blocking operation that starts the server listening on the DNS ports.
func (s *server) Run() error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	dnsReadyMsg := func(addr, net string) {
		if s.config.DNSSEC == "" {
			log.Printf("skydns: ready for queries on %s for %s://%s [rcache %d]", s.config.Domain, net, addr, s.config.RCache)
		} else {
			log.Printf("skydns: ready for queries on %s for %s://%s [rcache %d], signing with %s [scache %d]", s.config.Domain, net, addr, s.config.RCache, s.config.DNSSEC, s.config.SCache)
		}
	}

	if s.config.Systemd {
		packetConns, err := activation.PacketConns(false)
		if err != nil {
			return err
		}
		listeners, err := activation.Listeners(true)
		if err != nil {
			return err
		}
		if len(packetConns) == 0 && len(listeners) == 0 {
			return fmt.Errorf("no UDP or TCP sockets supplied by systemd")
		}
		for _, p := range packetConns {
			if u, ok := p.(*net.UDPConn); ok {
				s.group.Add(1)
				go func() {
					defer s.group.Done()
					if err := dns.ActivateAndServe(nil, u, mux); err != nil {
						log.Fatalf("skydns: %s", err)
					}
				}()
				dnsReadyMsg(u.LocalAddr().String(), "udp")
			}
		}
		for _, l := range listeners {
			if t, ok := l.(*net.TCPListener); ok {
				s.group.Add(1)
				go func() {
					defer s.group.Done()
					if err := dns.ActivateAndServe(t, nil, mux); err != nil {
						log.Fatalf("skydns: %s", err)
					}
				}()
				dnsReadyMsg(t.Addr().String(), "tcp")
			}
		}
	} else {
		s.group.Add(1)
		go func() {
			defer s.group.Done()
			if err := dns.ListenAndServe(s.config.DnsAddr, "tcp", mux); err != nil {
				log.Fatalf("skydns: %s", err)
			}
		}()
		dnsReadyMsg(s.config.DnsAddr, "tcp")
		s.group.Add(1)
		go func() {
			defer s.group.Done()
			if err := dns.ListenAndServe(s.config.DnsAddr, "udp", mux); err != nil {
				log.Fatalf("skydns: %s", err)
			}
		}()
		dnsReadyMsg(s.config.DnsAddr, "udp")
	}

	s.group.Wait()
	return nil
}

// Stop stops a server.
func (s *server) Stop() {
	// TODO(miek)
	//s.group.Add(-2)
}

// ServeDNS is the handler for DNS requests, responsible for parsing DNS request, possibly forwarding
// it to a real dns server and returning a response.
func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Compress = true
	bufsize := uint16(512)
	dnssec := false
	tcp := false

	if req.Question[0].Qtype == dns.TypeANY {
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		m.RecursionAvailable = false
		m.RecursionDesired = false
		m.Compress = false
		// if write fails don't care
		w.WriteMsg(m)
		return
	}

	if o := req.IsEdns0(); o != nil {
		bufsize = o.UDPSize()
		dnssec = o.Do()
	}
	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		bufsize = dns.MaxMsgSize - 1
		tcp = true
	}
	// Check cache first.
	key := cache.QuestionKey(req.Question[0], dnssec)
	m1, exp, hit := s.rcache.Search(key)
	if hit {
		// Cache hit! \o/
		if time.Since(exp) < 0 {
			m1.Id = m.Id
			m1.Compress = true
			if dnssec {
				StatsDnssecOkCount.Inc(1)
				// The key for DNS/DNSSEC in cache is different, no
				// need to do Denial/Sign here.
				//if s.config.PubKey != nil {
				//s.Denial(m1) // not needed for cache hits
				//s.Sign(m1, bufsize)
				//}
			}
			if m1.Len() > int(bufsize) && !tcp {
				m1.Truncated = true
			}
			// Still round-robin even with hits from the cache.
			// Only shuffle A and AAAA records with each other.
			if req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA {
				s.RoundRobin(m1.Answer)
			}

			if err := w.WriteMsg(m1); err != nil {
				log.Printf("skydns: failure to return reply %q", err)
			}
			return
		}
		// Expired! /o\
		s.rcache.Remove(key)
	}

	q := req.Question[0]
	name := strings.ToLower(q.Name)
	StatsRequestCount.Inc(1)
	if s.config.Verbose {
		log.Printf("skydns: received DNS Request for %q from %q with type %d", q.Name, w.RemoteAddr(), q.Qtype)
	}
	// If the qname is local.dns.skydns.local. and s.config.Local != "", substitute that name.
	if s.config.Local != "" && name == s.config.localDomain {
		name = s.config.Local
	}

	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		s.ServeDNSReverse(w, req)
		return
	}

	if q.Qclass != dns.ClassCHAOS && !strings.HasSuffix(name, s.config.Domain) {
		s.ServeDNSForward(w, req)
		return
	}

	defer func() {
		if m.Rcode == dns.RcodeServerFailure {
			if err := w.WriteMsg(m); err != nil {
				log.Printf("skydns: failure to return reply %q", err)
			}
			return
		}
		// Set TTL to the minimum of the RRset.
		minttl := s.config.Ttl
		if len(m.Answer) > 1 {
			for _, r := range m.Answer {
				if r.Header().Ttl < minttl {
					minttl = r.Header().Ttl
				}
			}
			for _, r := range m.Answer {
				r.Header().Ttl = minttl
			}
		}

		s.rcache.InsertMessage(cache.QuestionKey(req.Question[0], dnssec), m)

		if dnssec {
			StatsDnssecOkCount.Inc(1)
			if s.config.PubKey != nil {
				m.AuthenticatedData = true
				s.Denial(m)
				s.Sign(m, bufsize)
			}
		}
		if m.Len() > int(bufsize) && !tcp {
			// TODO(miek): this is a little brain dead, better is to not add
			// RRs in the message in the first place.
			m.Truncated = true
		}
		if err := w.WriteMsg(m); err != nil {
			log.Printf("skydns: failure to return reply %q", err)
		}
	}()

	if name == s.config.Domain {
		if q.Qtype == dns.TypeSOA {
			m.Answer = []dns.RR{s.NewSOA()}
			return
		}
		if q.Qtype == dns.TypeDNSKEY {
			if s.config.PubKey != nil {
				m.Answer = []dns.RR{s.config.PubKey}
				return
			}
		}
	}
	if q.Qclass == dns.ClassCHAOS {
		if q.Qtype == dns.TypeTXT {
			switch name {
			case "authors.bind.":
				fallthrough
			case s.config.Domain:
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				authors := []string{"Erik St. Martin", "Brian Ketelsen", "Miek Gieben", "Michael Crosby"}
				for _, a := range authors {
					m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{a}})
				}
				for j := 0; j < len(authors)*(int(dns.Id())%4+1); j++ {
					q := int(dns.Id()) % len(authors)
					p := int(dns.Id()) % len(authors)
					if q == p {
						p = (p + 1) % len(authors)
					}
					m.Answer[q], m.Answer[p] = m.Answer[p], m.Answer[q]
				}
				return
			case "version.bind.":
				fallthrough
			case "version.server.":
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{Version}}}
				return
			case "hostname.bind.":
				fallthrough
			case "id.server.":
				// TODO(miek): machine name to return
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"localhost"}}}
				return
			}
		}
		// still here, fail
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		return
	}

	switch q.Qtype {
	case dns.TypeNS:
		if name != s.config.Domain {
			break
		}
		// Lookup s.config.DnsDomain
		records, extra, err := s.NSRecords(q, s.config.dnsDomain)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					s.NameError(m, req)
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	case dns.TypeA, dns.TypeAAAA:
		records, err := s.AddressRecords(q, name, nil)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					s.NameError(m, req)
					return
				}
			}
			if err.Error() == "incomplete CNAME chain" {
				// We can not complete the CNAME internally, *iff* there is a
				// external name in the set, take it, and try to resolve it externally.
				if len(records) == 0 {
					s.NameError(m, req)
					return
				}
				target := ""
				for _, r := range records {
					if v, ok := r.(*dns.CNAME); ok {
						if !dns.IsSubDomain(s.config.Domain, v.Target) {
							target = v.Target
							break
						}
					}
				}
				if target == "" {
					log.Printf("skydns: incomplete CNAME chain for %s", name)
					s.NoDataError(m, req)
					return
				}
				m1, e1 := s.Lookup(target, req.Question[0].Qtype, bufsize, dnssec)
				if e1 != nil {
					log.Printf("skydns: %s", err)
					s.NoDataError(m, req)
					return
				}
				records = append(records, m1.Answer...)
			}
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeTXT:
		records, err := s.TXTRecords(q, name)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					s.NameError(m, req)
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeCNAME:
		records, err := s.CNAMERecords(q, name)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					s.NameError(m, req)
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
	default:
		fallthrough // also catch other types, so that they return NODATA
	case dns.TypeSRV, dns.TypeANY:
		records, extra, err := s.SRVRecords(q, name, bufsize, dnssec)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					s.NameError(m, req)
					return
				}
			}
		}
		// if we are here again, check the types, because an answer may only
		// be given for SRV or ANY. All other types should return NODATA, the
		// NXDOMAIN part is handled in the above code. TODO(miek): yes this
		// can be done in a more elegant manor.
		if q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeANY {
			m.Answer = append(m.Answer, records...)
			m.Extra = append(m.Extra, extra...)
		}
	}

	if len(m.Answer) == 0 { // NODATA response
		StatsNoDataCount.Inc(1)
		m.Ns = []dns.RR{s.NewSOA()}
		m.Ns[0].Header().Ttl = s.config.MinTtl
	}
}

func (s *server) AddressRecords(q dns.Question, name string, previousRecords []dns.RR) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, err
	}
	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			// TODO: deduplicate with above code
			// Try to resolve as CNAME if it's not an IP.
			newRecord := serv.NewCNAME(q.Name, dns.Fqdn(serv.Host))
			if len(previousRecords) > 7 {
				log.Printf("skydns: CNAME lookup limit of 8 exceeded for %s", newRecord)
				return nil, fmt.Errorf("exceeded CNAME lookup limit")
			}
			if s.isDuplicateCNAME(newRecord, previousRecords) {
				log.Printf("skydns: CNAME loop detected for record %s", newRecord)
				return nil, fmt.Errorf("detected CNAME loop")
			}

			records = append(records, newRecord)
			nextRecords, err := s.AddressRecords(dns.Question{Name: dns.Fqdn(serv.Host), Qtype: q.Qtype, Qclass: q.Qclass}, strings.ToLower(dns.Fqdn(serv.Host)), append(previousRecords, newRecord))
			if err != nil {
				// This means we can not complete the CNAME, this is OK, but
				// if we return an error this will trigger an NXDOMAIN.
				// We also don't want to return the CNAME, because of the
				// no other data rule. So return nothing and let NODATA
				// kick in (via a hack).
				return records, fmt.Errorf("incomplete CNAME chain")
			}
			records = append(records, nextRecords...)
		case ip.To4() != nil && q.Qtype == dns.TypeA:
			records = append(records, serv.NewA(q.Name, ip.To4()))
		case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
			records = append(records, serv.NewAAAA(q.Name, ip.To16()))
		}
	}
	if s.config.RoundRobin {
		s.RoundRobin(records)
	}
	return records, nil
}

// NSRecords returns NS records from etcd.
func (s *server) NSRecords(q dns.Question, name string) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

// SRVRecords returns SRV records from etcd.
// If the Target is not an name but an IP address, an name is created .
func (s *server) SRVRecords(q dns.Question, name string, bufsize uint16, dnssec bool) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	// Looping twice to get the right weight vs priority
	w := make(map[int]int)
	for _, serv := range services {
		weight := 100
		if serv.Weight != 0 {
			weight = serv.Weight
		}
		if _, ok := w[serv.Priority]; !ok {
			w[serv.Priority] = weight
			continue
		}
		w[serv.Priority] += weight
	}
	lookup := make(map[string]bool)
	for _, serv := range services {
		w1 := 100.0 / float64(w[serv.Priority])
		if serv.Weight == 0 {
			w1 *= 100
		} else {
			w1 *= float64(serv.Weight)
		}
		weight := uint16(math.Floor(w1))
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			srv := serv.NewSRV(q.Name, weight)
			records = append(records, srv)
			if _, ok := lookup[srv.Target]; !ok {
				if !dns.IsSubDomain(s.config.Domain, srv.Target) {
					m1, e1 := s.Lookup(srv.Target, dns.TypeA, bufsize, dnssec)
					if e1 == nil {
						extra = append(extra, m1.Answer...)
					}
					m1, e1 = s.Lookup(srv.Target, dns.TypeAAAA, bufsize, dnssec)
					if e1 == nil {
						// If we have seen CNAME's we *assume* that they are already added.
						for _, a := range m1.Answer {
							if _, ok := a.(*dns.CNAME); !ok {
								extra = append(extra, a)
							}
						}
					}
				}
			}
			lookup[srv.Target] = true
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewSRV(q.Name, weight))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewSRV(q.Name, weight))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

func (s *server) CNAMERecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, true)
	if err != nil {
		return nil, err
	}

	if len(services) > 0 {
		serv := services[0]
		if ip := net.ParseIP(serv.Host); ip == nil {
			records = append(records, serv.NewCNAME(q.Name, dns.Fqdn(serv.Host)))
		}
	}
	return records, nil
}

func (s *server) TXTRecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, err
	}

	for _, serv := range services {
		if serv.Text == "" {
			continue
		}
		records = append(records, serv.NewTXT(q.Name))
	}
	return records, nil
}

func (s *server) PTRRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	serv, err := s.backend.ReverseRecord(name)
	if err != nil {
		return nil, err
	}

	// If serv.Host is parseble as a IP address we should not return anything.
	// TODO(miek).
	records = append(records, serv.NewPTR(q.Name, serv.Ttl))
	return records, nil
}

// SOA returns a SOA record for this SkyDNS instance.
func (s *server) NewSOA() dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: s.config.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.config.Ttl},
		Ns:      appendDomain("ns.dns", s.config.Domain),
		Mbox:    s.config.Hostmaster,
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  s.config.MinTtl,
	}
}

func (s *server) isDuplicateCNAME(r *dns.CNAME, records []dns.RR) bool {
	for _, rec := range records {
		if v, ok := rec.(*dns.CNAME); ok {
			if v.Target == r.Target {
				return true
			}
		}
	}
	return false
}

func (s *server) NameError(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{s.NewSOA()}
	m.Ns[0].Header().Ttl = s.config.MinTtl
	StatsNameErrorCount.Inc(1)
}

func (s *server) NoDataError(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeSuccess)
	m.Ns = []dns.RR{s.NewSOA()}
	m.Ns[0].Header().Ttl = s.config.MinTtl
	//	StatsNoDataCount.Inc(1)
}

func (s *server) logNoConnection(e error) {
	if e.(*etcd.EtcdError).ErrorCode == etcd.ErrCodeEtcdNotReachable {
		log.Printf("skydns: failure to connect to etcd: %s", e)
	}
}

func (s *server) RoundRobin(rrs []dns.RR) {
	if !s.config.RoundRobin {
		return
	}
	// If we have more than 1 CNAME don't touch the packet, because some stub resolver (=glibc)
	// can't deal with the returned packet if the CNAMEs need to be accesses in the reverse order.
	cname := 0
	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeCNAME {
			cname++
			if cname > 1 {
				return
			}
		}
	}

	switch l := len(rrs); l {
	case 2:
		if dns.Id()%2 == 0 {
			rrs[0], rrs[1] = rrs[1], rrs[0]
		}
	default:
		for j := 0; j < l*(int(dns.Id())%4+1); j++ {
			q := int(dns.Id()) % l
			p := int(dns.Id()) % l
			if q == p {
				p = (p + 1) % l
			}
			rrs[q], rrs[p] = rrs[p], rrs[q]
		}
	}

}
