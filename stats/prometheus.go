// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/skynetservices/skydns/server"
)

func init() {
	server.StatsForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_forward_count",
		Help: "Counter of DNS requests forwarded",
	})

	server.StatsStubForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_stub_forward_count",
		Help: "Counter of DNS requests forwarded to stubs",
	})

	server.StatsLookupCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_lookup_count",
		Help: "Counter of DNS lookups performed",
	})

	server.StatsRequestCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_request_count",
		Help: "Counter of DNS requests made",
	})

	server.StatsDnssecOkCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dnssec_ok_count",
		Help: "Counter of DNSSEC requests",
	})

	server.StatsDnssecCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dnssec_cache_miss_count",
		Help: "Counter of DNSSEC requests that missed the cache",
	})

	server.StatsNameErrorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_name_error_count",
		Help: "Counter of DNS requests resulting in a name error",
	})

	server.StatsNoDataCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_no_data_count",
		Help: "Counter of DNS requests that contained no data",
	})

	server.StatsRCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rcache_total_size",
		Help: "The total size of all RRs in the rcache.",
	})
	server.StatsSCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "scache_total_size",
		Help: "The total size of all RRSIGs in the scache.",
	})
}
