// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
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
	domainLabels int
	client       *etcd.Client
	config       *Config

	group *sync.WaitGroup
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
	go runDNSServer(s.group, mux, "tcp", s.config.DnsAddr, 0, s.config.WriteTimeout, s.config.ReadTimeout)
	go runDNSServer(s.group, mux, "udp", s.config.DnsAddr, 0, s.config.WriteTimeout, s.config.ReadTimeout)

	s.group.Wait()
	return nil
}

// Stop stops a server.
func (s *server) Stop() {
	//s.group.Add(-2)
}

func runDNSServer(group *sync.WaitGroup, mux *dns.ServeMux, net, addr string, udpsize int, writeTimeout, readTimeout time.Duration) {
	defer group.Done()

	server := &dns.Server{
		Addr:         addr,
		Net:          net,
		Handler:      mux,
		UDPSize:      udpsize,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
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
		if s.config.PubKey != nil {
			if opt := req.IsEdns0(); opt != nil && opt.Do() {
				s.NewNSEC(m)
				s.sign(m, opt.UDPSize())
			}
		}
		w.WriteMsg(m)
	}()

	if name == s.config.Domain {
		switch q.Qtype {
		case dns.TypeDNSKEY:
			if s.config.PubKey != nil {
				m.Answer = append(m.Answer, s.config.PubKey)
				return
			}
		case dns.TypeSOA:
			m.Answer = []dns.RR{s.NewSOA()}
			return
		}
	}
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		records, err := s.AddressRecords(q)
		if err != nil {
			if e, ok := err.(*etcd.EtcdError); ok {
				if e.ErrorCode == 100 {
					m.SetRcode(req, dns.RcodeNameError)
					m.Ns = []dns.RR{s.NewSOA()}
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
					return
				}
			}
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	}
	if len(m.Answer) == 0 { // NODATA response
		m.Ns = []dns.RR{s.NewSOA()}
	}
}

// ServeDNSForward forwards a request to a nameservers and returns the response.
func (s *server) ServeDNSForward(w dns.ResponseWriter, req *dns.Msg) {
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

	// Use request Id for "random" nameserver selection
	nsid := int(req.Id) % len(s.config.Nameservers)
	try := 0
Redo:
	r, _, err := c.Exchange(req, s.config.Nameservers[nsid])
	if err == nil {
		w.WriteMsg(r)
		return
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers
	if try < len(s.config.Nameservers) {
		try++
		nsid = (nsid + 1) % len(s.config.Nameservers)
		goto Redo
	}

	log.Printf("error: failure to forward request %q", err)
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func (s *server) AddressRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	if name == "master."+s.config.Domain || name == s.config.Domain {
		for _, m := range s.client.GetCluster() {
			u, e := url.Parse(m)
			if e != nil {
				continue
			}
			h, _, e := net.SplitHostPort(u.Host)
			if e != nil {
				continue
			}
			ip := net.ParseIP(h)
			serv := new(Service) // noop for now, but will be actually do something when create A/AAAA
			switch {
			case ip.To4() != nil && q.Qtype == dns.TypeA:
				records = append(records, serv.NewA(q.Name, s.config.Ttl, ip.To4()))
			case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
				records = append(records, serv.NewAAAA(q.Name, s.config.Ttl, ip.To16()))
			}
		}
		return
	}
	path, star := Path(name)
	r, err := s.client.Get(path, false, true)
	if err != nil {
		return nil, err
	}
	if !r.Node.Dir { // single element
		var serv *Service
		if err := json.Unmarshal([]byte(r.Node.Value), &serv); err != nil {
			return nil, err
		}
		ip := net.ParseIP(serv.Host)
		ttl := uint32(r.Node.TTL)
		if ttl == 0 {
			ttl = s.config.Ttl
		}
		switch {
		case ip == nil:
		case ip.To4() != nil && q.Qtype == dns.TypeA:
			records = append(records, serv.NewA(q.Name, ttl, ip.To4()))
		case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
			records = append(records, serv.NewAAAA(q.Name, ttl, ip.To16()))
		}
		return records, nil
	}
	nodes, err := s.loopNodes(&r.Node.Nodes, strings.Split(PathNoWildcard(name), "/"), star)
	if err != nil {
		return nil, err
	}
	for _, serv := range nodes {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
		case ip.To4() != nil && q.Qtype == dns.TypeA:
			records = append(records, serv.NewA(q.Name, serv.ttl, ip.To4()))
		case ip.To4() == nil && q.Qtype == dns.TypeAAAA:
			records = append(records, serv.NewAAAA(q.Name, serv.ttl, ip.To16()))
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
	weight := uint16(0)
	if !r.Node.Dir { // single element
		var serv *Service
		if err := json.Unmarshal([]byte(r.Node.Value), &serv); err != nil {
			return nil, nil, err
		}
		ip := net.ParseIP(serv.Host)
		ttl := uint32(r.Node.TTL)
		if ttl == 0 {
			ttl = s.config.Ttl
		}
		if serv.Priority == 0 {
			serv.Priority = int(s.config.Priority)
		}
		switch {
		case ip == nil:
			records = append(records, serv.NewSRV(q.Name, ttl, weight))
		case ip.To4() != nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, ttl, weight))
			extra = append(extra, serv.NewA(Domain(r.Node.Key), ttl, ip.To4()))
		case ip.To4() == nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, ttl, weight))
			extra = append(extra, serv.NewAAAA(Domain(r.Node.Key), ttl, ip.To16()))
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
	weight = uint16(math.Floor(float64(100 / len(sx))))
	for _, serv := range sx {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			records = append(records, serv.NewSRV(q.Name, serv.ttl, weight))
		case ip.To4() != nil:
			serv.Host = Domain(serv.key) // TODO(miek): ugly
			records = append(records, serv.NewSRV(q.Name, serv.ttl, weight))
			extra = append(extra, serv.NewA(Domain(serv.key), serv.ttl, ip.To4()))
		case ip.To4() == nil:
			serv.Host = Domain(serv.key)
			records = append(records, serv.NewSRV(q.Name, serv.ttl, weight))
			extra = append(extra, serv.NewAAAA(Domain(serv.key), serv.ttl, ip.To16()))
		}
	}
	return records, extra, nil
}

// SOA returns a SOA record for this SkyDNS instance.
func (s *server) NewSOA() dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: s.config.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.config.Ttl},
		Ns:      "master." + s.config.Domain,
		Mbox:    "hostmaster." + s.config.Domain,
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
		if err := json.Unmarshal([]byte(n.Value), &serv); err != nil {
			return nil, err
		}
		serv.ttl = uint32(n.TTL)
		if serv.ttl == 0 {
			serv.ttl = s.config.Ttl
		}
		if serv.Priority == 0 {
			serv.Priority = int(s.config.Priority)
		}
		serv.key = n.Key
		sx = append(sx, serv)
	}
	return sx, nil
}
