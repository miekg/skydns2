package main

import (
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-etcd/etcd"
	"github.com/miekg/dns"
)

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

func toPath(s string) string {
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

// questionToPath converts a DNS question to a etcd key. If the questions looks
// like service.staging.skydns.local SRV, the resulting key
// will by /local/skydns/staging/service/SRV .
func questionToPath(q string, t uint16) string {
	return "/" + toPath(q) + "/" + dns.TypeToString[t]
}

// TODO(miek): TTL etc.
func parseValue(typ, value string) dns.RR {
	switch typ {
	case "A":
		a := new(dns.A)
		a.A, _ = parseA(value)
		return a
	case "AAAA":
		aaaa := new(dns.AAAA)
		aaaa.AAAA, _ = parseAAAA(value)
		return aaaa
	case "SRV":
		srv := new(dns.SRV)
		srv.Priority, srv.Weight, srv.Port, srv.Target, _ = parseSRV(value)
		return srv
	}
	return nil
}

// Create header here too.
func get(e *etcd.Client, path string) ([]dns.RR, error) {
	r, err := e.Get(path, false, false)
	if err != nil {
		return nil, err
	}
	// r.Response.Node.Value
	// Look in response r and extract stuff
	return nil, nil
}
