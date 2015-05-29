// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"

	"github.com/miekg/dns"
)

func newMetricServer(t *testing.T) *server {
	s := newTestServer(t, false)

	prometheusPort = "12300"
	prometheusNamespace = "test"

	Metrics()

	return s
}

func query(n string, t uint16) {
	m := new(dns.Msg)
	m.SetQuestion(n, t)
	dns.Exchange(m, "127.0.0.1:"+StrPort)
}

func scrape(t *testing.T, key string) int {
	resp, err := http.Get("http://localhost:12300/metrics")
	if err != nil {
		t.Fatal("could not get metrics")
	}

	body, _ := ioutil.ReadAll(resp.Body)

	// Find value for key.
	n := bytes.Index(body, []byte(key))
	i := n
	for i < len(body) {
		if body[i] == '\n' {
			break
		}
		if body[i] == ' ' {
			n = i + 1
		}
		i++
	}
	value, err := strconv.Atoi(string(body[n:i]))
	if err != nil {
		t.Fatal("failed to get value")
	}
	return value
}

func TestMetricRequests(t *testing.T) {
	s := newMetricServer(t)
	defer s.Stop()

	query("miek.nl.", dns.TypeMX)
	v := scrape(t, "test_dns_request_count{type=\"udp\"}")
	if v != 1 {
		t.Fatalf("expecting %d, got %d", 1, v)
	}
	v = scrape(t, "test_dns_request_count{type=\"total\"}")
	if v != 1 {
		t.Fatalf("expecting %d, got %d", 1, v)
	}
}
