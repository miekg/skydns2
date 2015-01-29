// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"net"
	"os"

	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/stathat"
)

var (
	StatsForwardCount    metrics.Counter
	StatsLookupCount     metrics.Counter
	StatsRequestCount    metrics.Counter
	StatsDnssecOkCount   metrics.Counter
	StatsDnssecCacheMiss metrics.Counter
	StatsNameErrorCount  metrics.Counter
	StatsNoDataCount     metrics.Counter

	graphiteServer = os.Getenv("GRAPHITE_SERVER")
	graphitePrefix = os.Getenv("GRAPHITE_PREFIX")
	stathatUser    = os.Getenv("STATHAT_USER")
)

func init() {
	if graphitePrefix == "" {
		graphitePrefix = "skydns"
	}

	StatsForwardCount = metrics.NewCounter()
	metrics.Register("skydns-forward-requests", StatsForwardCount)

	StatsDnssecOkCount = metrics.NewCounter()
	metrics.Register("skydns-dnssecok-requests", StatsDnssecOkCount)

	StatsDnssecCacheMiss = metrics.NewCounter()
	metrics.Register("skydns-dnssec-cache-miss", StatsDnssecCacheMiss)

	StatsLookupCount = metrics.NewCounter()
	metrics.Register("skydns-internal-lookups", StatsLookupCount)

	StatsRequestCount = metrics.NewCounter()
	metrics.Register("skydns-requests", StatsRequestCount)

	StatsNameErrorCount = metrics.NewCounter()
	metrics.Register("skydns-nameerror-responses", StatsNameErrorCount)

	StatsNoDataCount = metrics.NewCounter()
	metrics.Register("skydns-nodata-responses", StatsNoDataCount)
}

func StatsCollect() {
	if graphiteServer != "" {
		addr, err := net.ResolveTCPAddr("tcp", graphiteServer)
		if err == nil {
			go metrics.Graphite(metrics.DefaultRegistry, 10e9, graphitePrefix, addr)
		}
	}

	if stathatUser != "" {
		go stathat.Stathat(metrics.DefaultRegistry, 10e9, stathatUser)
	}
}
