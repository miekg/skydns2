package main

import (
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
)

// we put the names in the reverse domain
// bla.blie.skydns.local becomes
// local/skydns/blie/bla/srv where we put the rdata
// last element must be A AAAA or SRV

func toValue(rr dns.RR) string {
	switch x := rr.(type) {
	case *dns.A:
		return x.A.String()
	case *dns.AAAA:
		return x.AAAA.String()
	case *dns.SRV:
		return strconv.Itoa(int(x.Priority)) + " " +
			strconv.Itoa(int(x.Weight)) + " " +
			strconv.Itoa(int(x.Port)) + " " + dns.Name(x.Target).String()
	}
	return ""
}

func toKey(s string) string {
	l := dns.SplitDomainName(s)
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	// TODO(miek): escape slashes in s.
	return strings.Join(l, "/")
}

func parseA(v string) (net.IP, error)    { return net.ParseIP(v).To4(), nil }
func parseAAAA(v string) (net.IP, error) { return net.ParseIP(v).To16(), nil }
func parseSRV(v string) (uint16, uint16, uint16, string, error) {
	p := strings.Split(v, " ")
	prio, _ := strconv.Atoi(p[0])
	weight, _ := strconv.Atoi(p[1])
	port, _ := strconv.Atoi(p[2])
	return uint16(prio), uint16(weight), uint16(port), p[3], nil
}

// Convert a DNS question to a etcd key. If the questions looks
// like service.staging.skydns.local SRV, the resulting key
// will by /local/skydns/staging/service/SRV .
func QuestionToKey(q string, t uint16) string {
	return "/" + toKey(q) + "/" + dns.TypeToString[t]
}
