// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"log"

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
	// StatsStubForwardcount.Inc(1)
	log.Printf("skydns: stub zone forward")
}
