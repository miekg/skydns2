// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/miekg/dns"
)

type server struct {
	client *etcd.Client
	config *Config
	group  *sync.WaitGroup
}

// Newserver returns a new server.
func NewServer(config *Config, client *etcd.Client) *server {
	return &server{client: client, config: config, group: new(sync.WaitGroup)}
}

// Run is a blocking operation that starts the server listening on the DNS ports.
func (s *server) Run() error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	s.group.Add(2)
	go runDNSServer(s.group, mux, "tcp", s.config.DnsAddr, s.config.ReadTimeout)
	go runDNSServer(s.group, mux, "udp", s.config.DnsAddr, s.config.ReadTimeout)
	s.config.log.Printf("connected to etcd cluster at %s", machines)

	s.group.Wait()
	return nil
}

// Stop stops a server.
func (s *server) Stop() {
	// TODO(miek)
	//s.group.Add(-2)
}

func runDNSServer(group *sync.WaitGroup, mux *dns.ServeMux, net, addr string, readTimeout time.Duration) {
	defer group.Done()

	server := &dns.Server{
		Addr:        addr,
		Net:         net,
		Handler:     mux,
		ReadTimeout: readTimeout,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// ServeDNS is the handler for DNS requests, responsible for parsing DNS request, possibly forwarding
// it to a real dns server and returning a response.
func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	StatsRequestCount.Inc(1)

	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		s.ServeDNSReverse(w, req)
		return
	}

	if !strings.HasSuffix(name, s.config.Domain) {
		s.ServeDNSForward(w, req)
		return
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Answer = make([]dns.RR, 0, 10)
	defer func() {
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
		// Check if we need to do DNSSEC and sign the reply.
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			StatsDnssecOkCount.Inc(1)
			if s.config.PubKey != nil {
				s.Denial(m)
				s.sign(m, opt.UDPSize())
			}
		}
		w.WriteMsg(m)
	}()

	if strings.HasSuffix(name, "dns."+s.config.Domain) || name == s.config.Domain {
		// As we hijack dns.skydns.local we need to return NODATA for that name.
		if name == "dns."+s.config.Domain {
			m.Ns = []dns.RR{s.NewSOA()}
			return
		}
		if q.Qtype == dns.TypeSOA && name == s.config.Domain {
			m.Answer = []dns.RR{s.NewSOA()}
			return
		}
		if q.Qtype == dns.TypeDNSKEY && name == s.config.Domain {
			if s.config.PubKey != nil {
				m.Answer = append(m.Answer, s.config.PubKey)
				return
			}
		}
		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeTXT && name == s.config.Domain {
			hdr := dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
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
		}
		for i, c := range s.client.GetCluster() {
			u, e := url.Parse(c)
			if e != nil {
				continue
			}
			h, _, e := net.SplitHostPort(u.Host)
			if e != nil {
				continue
			}
			ip := net.ParseIP(h)
			serv := new(Service)
			serv.Ttl = s.config.Ttl
			switch {
			case name == s.config.Domain && q.Qtype == dns.TypeNS:
				m.Answer = append(m.Answer, serv.NewNS(s.config.Domain, fmt.Sprintf("ns%d.dns.%s", i+1, s.config.Domain)))
			case ip.To4() != nil && q.Qtype == dns.TypeA && q.Name == fmt.Sprintf("ns%d.dns.%s", i+1, s.config.Domain):
				m.Answer = append(m.Answer, serv.NewA(q.Name, ip.To4()))
			case ip.To4() == nil && q.Qtype == dns.TypeAAAA && q.Name == fmt.Sprintf("ns%d.dns.%s", i+1, s.config.Domain):
				m.Answer = append(m.Answer, serv.NewAAAA(q.Name, ip.To16()))
			}
		}
		if len(m.Answer) > 0 {
			return
		}
	}

	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		records, err := s.AddressRecords(q, nil)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					m.SetRcode(req, dns.RcodeNameError)
					m.Ns = []dns.RR{s.NewSOA()}
					m.Ns[0].Header().Ttl = s.config.MinTtl
					StatsNameErrorCount.Inc(1)
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
	}
	if q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeANY {
		records, extra, err := s.SRVRecords(q)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					m.SetRcode(req, dns.RcodeNameError)
					m.Ns = []dns.RR{s.NewSOA()}
					m.Ns[0].Header().Ttl = s.config.MinTtl
					StatsNameErrorCount.Inc(1)
					return
				}
			}
			// Hack alert, TODO:(miek)
			if err.Error() == "incomplete CNAME chain" {
				m.SetRcode(req, dns.RcodeNameError)
				m.Ns = []dns.RR{s.NewSOA()}
				m.Ns[0].Header().Ttl = s.config.MinTtl
				StatsNameErrorCount.Inc(1)
				return
			}
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	}
	if q.Qtype == dns.TypeCNAME {
		records, err := s.CNAMERecords(q)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					m.SetRcode(req, dns.RcodeNameError)
					m.Ns = []dns.RR{s.NewSOA()}
					m.Ns[0].Header().Ttl = s.config.MinTtl
					StatsNameErrorCount.Inc(1)
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
	}
	if len(m.Answer) == 0 { // NODATA response
		StatsNoDataCount.Inc(1)
		m.Ns = []dns.RR{s.NewSOA()}
		m.Ns[0].Header().Ttl = s.config.MinTtl
	}
}

// ServeDNSForward forwards a request to a nameservers and returns the response.
func (s *server) ServeDNSForward(w dns.ResponseWriter, req *dns.Msg) {
	StatsDnssecOkCount.Inc(1)
	if len(s.config.Nameservers) == 0 {
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.Authoritative = false     // no matter what set to false
		m.RecursionAvailable = true // and this is still true
		w.WriteMsg(m)
		return
	}
	network := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}

	c := &dns.Client{Net: network, ReadTimeout: s.config.ReadTimeout}

	// Use request Id for "random" nameserver selection.
	nsid := int(req.Id) % len(s.config.Nameservers)
	try := 0
Redo:
	r, _, err := c.Exchange(req, s.config.Nameservers[nsid])
	if err == nil {
		w.WriteMsg(r)
		return
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers.
	if try < len(s.config.Nameservers) {
		try++
		nsid = (nsid + 1) % len(s.config.Nameservers)
		goto Redo
	}

	s.config.log.Errorf("failure to forward request %q", err)
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

// ServeDNSReverse is the handler for DNS requests for the reverse zone. If nothing is found
// locally the request is forwarded to the forwarder for resolution.
func (s *server) ServeDNSReverse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false // Set to false, because I don't know what to do wrt DNSSEC.
	m.RecursionAvailable = true
	var err error
	if m.Answer, err = s.PTRRecords(req.Question[0]); err == nil {
		// TODO(miek): Reverse DNSSEC. We should sign this, but requires a key....and more
		// Probably not worth the hassle?
		w.WriteMsg(m)
	}
	// Always forward if not found locally.
	s.ServeDNSForward(w, req)
}

func (s *server) AddressRecords(q dns.Question, previousRecords []dns.RR) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	path, star := Path(name)
	r, err := s.client.Get(path, false, true)
	if err != nil {
		return nil, err
	}
	if !r.Node.Dir { // single element
		serv := new(Service)
		if err := json.Unmarshal([]byte(r.Node.Value), serv); err != nil {
			s.config.log.Infof("failed to parse json: %s", err.Error())
			return nil, err
		}
		ip := net.ParseIP(serv.Host)
		ttl := s.calculateTtl(r.Node, serv)
		serv.Ttl = ttl
		serv.key = r.Node.Key
		switch {
		case ip == nil:
			// Try to resolve as CNAME if it's not an IP.
			newRecord := serv.NewCNAME(q.Name, dns.Fqdn(serv.Host))
			if len(previousRecords) > 7 {
				s.config.log.Errorf("CNAME lookup limit of 8 exceeded for %s", newRecord)
				return nil, fmt.Errorf("exceeded CNAME lookup limit")
			}
			if s.isDuplicateCNAME(newRecord, previousRecords) {
				s.config.log.Errorf("CNAME loop detected for record %s", newRecord)
				return nil, fmt.Errorf("detected CNAME loop")
			}

			records = append(records, newRecord)
			nextRecords, err := s.AddressRecords(dns.Question{Name: dns.Fqdn(serv.Host), Qtype: q.Qtype, Qclass: q.Qclass}, append(previousRecords, newRecord))
			if err != nil {
				// This means we can not complete the CNAME, this is OK, but
				// if we return an error this will trigger an NXDOMAIN.
				// We also don't want to return the CNAME, because of the
				// no other data rule. So return nothing and let NODATA
				// kick in (via a hack).
				return nil, fmt.Errorf("incomplete CNAME chain")
			}
			records = append(records, nextRecords...)
		case ip.To4() != nil && q.Qtype == dns.TypeA:
			records = append(records, serv.NewA(q.Name, ip.To4()))
		case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
			records = append(records, serv.NewAAAA(q.Name, ip.To16()))
		}
		return records, nil
	}
	nodes, err := s.loopNodes(&r.Node.Nodes, strings.Split(PathNoWildcard(name), "/"), star)
	if err != nil {
		s.config.log.Infof("failed to parse json: %s", err.Error())
		return nil, err
	}
	for _, serv := range nodes {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
		case ip.To4() != nil && q.Qtype == dns.TypeA:
			records = append(records, serv.NewA(q.Name, ip.To4()))
		case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
			records = append(records, serv.NewAAAA(q.Name, ip.To16()))
		}
	}
	if s.config.RoundRobin {
		switch l := len(records); l {
		case 2:
			if dns.Id()%2 == 0 {
				records[0], records[1] = records[1], records[0]
			}
		default:
			// Do a minimum of l swap, maximum of 4l swaps
			for j := 0; j < l*(int(dns.Id())%4+1); j++ {
				q := int(dns.Id()) % l
				p := int(dns.Id()) % l
				if q == p {
					p = (p + 1) % l
				}
				records[q], records[p] = records[p], records[q]
			}
		}
	}
	return records, nil
}

// SRVRecords returns SRV records from etcd.
// If the Target is not an name but an IP address, an name is created .
func (s *server) SRVRecords(q dns.Question) (records []dns.RR, extra []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	path, star := Path(name)
	r, err := s.client.Get(path, false, true)
	if err != nil {
		return nil, nil, err
	}
	if !r.Node.Dir { // single element
		serv := new(Service)
		if err := json.Unmarshal([]byte(r.Node.Value), serv); err != nil {
			s.config.log.Infof("failed to parse json: %s", err.Error())
			return nil, nil, err
		}
		ip := net.ParseIP(serv.Host)
		ttl := s.calculateTtl(r.Node, serv)
		if serv.Priority == 0 {
			serv.Priority = int(s.config.Priority)
		}
		serv.key = r.Node.Key
		serv.Ttl = ttl
		switch {
		case ip == nil:
			records = append(records, serv.NewSRV(q.Name, uint16(100)))
		case ip.To4() != nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, uint16(100)))
			extra = append(extra, serv.NewA(Domain(r.Node.Key), ip.To4()))
		case ip.To4() == nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, uint16(100)))
			extra = append(extra, serv.NewAAAA(Domain(r.Node.Key), ip.To16()))
		}
		return records, extra, nil
	}

	sx, err := s.loopNodes(&r.Node.Nodes, strings.Split(PathNoWildcard(name), "/"), star)
	if err != nil {
		return nil, nil, err
	}
	if len(sx) == 0 {
		return nil, nil, nil
	}
	// Looping twice to get the right weight vs priority
	w := make(map[int]int)
	for _, serv := range sx {
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
	for _, serv := range sx {
		w1 := 100.0 / float64(w[serv.Priority])
		// adjust for a particular service
		if serv.Weight == 0 {
			w1 *= 100
		} else {
			w1 *= float64(serv.Weight)
		}
		weight := uint16(math.Floor(w1))
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			records = append(records, serv.NewSRV(q.Name,weight))
		case ip.To4() != nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, weight))
			extra = append(extra, serv.NewA(Domain(serv.key), ip.To4()))
		case ip.To4() == nil:
			serv.Host = Domain(serv.key)
			records = append(records, serv.NewSRV(q.Name, weight))
			extra = append(extra, serv.NewAAAA(Domain(serv.key), ip.To16()))
		}
	}
	return records, extra, nil
}

func (s *server) CNAMERecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	path, _ := Path(name) // no wildcards here
	r, err := s.client.Get(path, false, true)
	if err != nil {
		return nil, err
	}
	if !r.Node.Dir {
		serv := new(Service)
		if err := json.Unmarshal([]byte(r.Node.Value), serv); err != nil {
			s.config.log.Infof("failed to parse json: %s", err.Error())
			return nil, err
		}
		ip := net.ParseIP(serv.Host)
		ttl := s.calculateTtl(r.Node, serv)
		serv.key = r.Node.Key
		serv.Ttl = ttl
		if ip == nil {
			records = append(records, serv.NewCNAME(q.Name, dns.Fqdn(serv.Host)))
		}
	}
	return records, nil
}

func (s *server) PTRRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	path, star := Path(name)
	if star {
		return nil, fmt.Errorf("reverse can not contain wildcards")
	}
	r, err := s.client.Get(path, false, false)
	if err != nil {
		// if server has a forward, forward the query
		return nil, err
	}
	if r.Node.Dir {
		return nil, fmt.Errorf("reverse should not be a directory")
	}
	serv := new(Service)
	if err := json.Unmarshal([]byte(r.Node.Value), serv); err != nil {
		s.config.log.Infof("failed to parse json: %s", err.Error())
		return nil, err
	}
	ttl := uint32(r.Node.TTL)
	if ttl == 0 {
		ttl = s.config.Ttl
	}
	serv.key = r.Node.Key
	// If serv.Host is parseble as a IP address we should not return anything.
	// TODO(miek).
	records = append(records, serv.NewPTR(q.Name, ttl))
	return records, nil
}

// SOA returns a SOA record for this SkyDNS instance.
func (s *server) NewSOA() dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: s.config.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.config.Ttl},
		Ns:      "ns1.dns." + s.config.Domain,
		Mbox:    s.config.Hostmaster,
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  s.config.MinTtl,
	}
}

// skydns/local/skydns/east/staging/web
// skydns/local/skydns/west/production/web
//
// skydns/local/skydns/*/*/web
// skydns/local/skydns/*/web

// loopNodes recursively loops through the nodes and returns all the values. The nodes' keyname
// will be match against any wildcards when star is true.
func (s *server) loopNodes(n *etcd.Nodes, nameParts []string, star bool) (sx []*Service, err error) {
Nodes:
	for _, n := range *n {
		if n.Dir {
			nodes, err := s.loopNodes(&n.Nodes, nameParts, star)
			if err != nil {
				return nil, err
			}
			sx = append(sx, nodes...)
			continue
		}
		if star {
			keyParts := strings.Split(n.Key, "/")
			for i, n := range nameParts {
				if i > len(keyParts)-1 {
					// name is longer than key
					continue Nodes
				}
				if n == "*" {
					continue
				}
				if keyParts[i] != n {
					continue Nodes
				}
			}
		}
		serv := new(Service)
		if err := json.Unmarshal([]byte(n.Value), serv); err != nil {
			return nil, err
		}
		serv.Ttl = s.calculateTtl(n, serv)
		if serv.Priority == 0 {
			serv.Priority = int(s.config.Priority)
		}
		serv.key = n.Key
		sx = append(sx, serv)
	}
	return sx, nil
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

// calculateTtl returns the smaller of the etcd TTL and the service's
// TTL. If neither of these are set (have a zero value), the server
// default is used.
func (s *server) calculateTtl(node *etcd.Node, serv *Service) uint32 {
	etcd_ttl := uint32(node.TTL)

	if etcd_ttl == 0 && serv.Ttl == 0 {
		return s.config.Ttl
	}
	if etcd_ttl == 0 {
		return serv.Ttl
	}
	if serv.Ttl == 0 {
		return etcd_ttl
	}
	if etcd_ttl < serv.Ttl {
		return etcd_ttl
	}
	return serv.Ttl
}
