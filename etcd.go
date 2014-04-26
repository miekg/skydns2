package main

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// This file can be removed later I think.

// questionToPath convert a domainname to a etcd path. If the question
// looks like service.staging.skydns.local., the resulting key
// will by /local/skydns/staging/service .
func questionToPath(s string) string {
	l := dns.SplitDomainName(s)
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	// TODO(miek): escape slashes in s.
	return strings.Join(l, "/")
}

func parseSRV(v string) (uint16, uint16, uint16, string, error) {
	p := strings.Split(v, " ") // Stored as space separated values.
	prio, _ := strconv.Atoi(p[0])
	weight, _ := strconv.Atoi(p[1])
	port, _ := strconv.Atoi(p[2])
	return uint16(prio), uint16(weight), uint16(port), p[3], nil
}

func parseValue(t uint16, value string, h dns.RR_Header) dns.RR {
	switch t {
	case dns.TypeSRV:
		srv := new(dns.SRV)
		srv.Hdr = h
		srv.Priority, srv.Weight, srv.Port, srv.Target, _ = parseSRV(value)
		return srv
	}
	return nil
}
