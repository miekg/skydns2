// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

// Look in .../dns/stub/<domain>/xx for msg.Services. Loop through them
// extract <domain> and add them as forwarders (ip:port-combos) for
// the stubzones.
func (s *server) UpdateStubZones() {
	// do some fakery here in the beginning
	stubmap := make(map[string][]string)
	stubmap["miek.nl."] = []string{"172.16.0.1:54", "176.58.119.54:53"}

	// We can just uses the backend interface to get these records.

	s.config.stub = &stubmap
}

// ServeDNSForward forwards a request to a nameservers and returns the response.
func (s *server) ServeDNSStubForward(w dns.ResponseWriter, req *dns.Msg, ns []string) {
	StatsStubForwardCount.Inc(1)

	// Very similar to ServeDNSForward. Maybe refactor them both.

	tcp := false
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		tcp = true
	}

	var (
		r   *dns.Msg
		err error
		try int
	)
	// Use request Id for "random" nameserver selection.
	nsid := int(req.Id) % len(ns)
Redo:
	switch tcp {
	case false:
		r, _, err = s.dnsUDPclient.Exchange(req, ns[nsid])
	case true:
		r, _, err = s.dnsTCPclient.Exchange(req, ns[nsid])
	}
	if err == nil {
		r.Compress = true
		r.Id = req.Id
		w.WriteMsg(r)
		return
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers.
	if try < len(ns) {
		try++
		nsid = (nsid + 1) % len(ns)
		goto Redo
	}

	log.Printf("skydns: failure to forward stub request %q", err)
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}
