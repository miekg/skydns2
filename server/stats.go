// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	prometheusPort      = os.Getenv("PROMETHEUS_PORT")
	prometheusPath      = os.Getenv("PROMETHEUS_PATH")
	prometheusNamespace = os.Getenv("PROMETHEUS_NAMESPACE")
	prometheusSubsystem = os.Getenv("PROMETHEUS_SUBSYSTEM")
)

var (
	promForwardCount     prometheus.Counter
	promStubForwardCount prometheus.Counter
	promLookupCount      prometheus.Counter
	promRequestCount     *prometheus.CounterVec
	promDnssecOkCount    prometheus.Counter
	promNameErrorCount   prometheus.Counter
	promNoDataCount      prometheus.Counter
	promRCacheSize       prometheus.Gauge // Vec with rcache/scache
	promSCacheSize       prometheus.Gauge
	promRCacheMiss       prometheus.Counter // idem
	promSCacheMiss       prometheus.Counter
)

func Metrics() {
	if prometheusPort == "" {
		return
	}

	if prometheusPath == "" {
		prometheusPath = "/metrics"
	}
	if prometheusNamespace == "" {
		prometheusNamespace = "skydns"
	}

	promForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_forward_count",
		Help:      "Counter of DNS requests forwarded.",
	})

	promStubForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_stub_forward_count",
		Help:      "Counter of DNS requests forwarded to stubs.",
	})

	// convert to VEC and use labels
	promLookupCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_lookup_count",
		Help:      "Counter of DNS lookups performed.",
	})

	promRequestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_request_count",
		Help:      "Counter of total DNS requests made.",
	}, []string{"type"}, // total, udp, tcp
	)
	prometheus.MustRegister(promRequestCount)

	promDnssecOkCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_dnssec_ok_count",
		Help:      "Counter of DNSSEC requests.",
	})

	promNameErrorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_name_error_count",
		Help:      "Counter of DNS requests resulting in a name error.",
	})

	promNoDataCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_no_data_count",
		Help:      "Counter of DNS requests that contained no data.",
	})

	// Caches
	promRCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "rcache_total_size",
		Help:      "The total size of all DNS messages in the rcache.",
	})

	promSCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "scache_total_size",
		Help:      "The total size of all RRSIGs in the scache.",
	})

	promRCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_rcache_miss_count",
		Help:      "Counter of DNS requests that result in cache miss.",
	})

	promSCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_scache_miss_count",
		Help:      "Counter of signature requests that result in cache miss.",
	})

	prometheus.MustRegister(promForwardCount)
	prometheus.MustRegister(promStubForwardCount)
	prometheus.MustRegister(promLookupCount)

	prometheus.MustRegister(promDnssecOkCount)
	prometheus.MustRegister(promNameErrorCount)
	prometheus.MustRegister(promNoDataCount)
	prometheus.MustRegister(promRCacheSize)
	prometheus.MustRegister(promSCacheSize)
	prometheus.MustRegister(promRCacheMiss)
	prometheus.MustRegister(promSCacheMiss)

	_, err := strconv.Atoi(prometheusPort)
	if err != nil {
		return
	}

	http.Handle(prometheusPath, prometheus.Handler())
	go func() {
		log.Fatalf("skydns: %s", http.ListenAndServe(":"+prometheusPort, nil))
	}()
}

// Counter is the metric interface used by this package
type Counter interface {
	Inc(i int64)
}

type nopCounter struct{}

func (nopCounter) Inc(_ int64) {}

// These are the old stat variables defined by this package. This
// used by graphite.
var (
	// Pondering deletion in favor of the better and more
	// maintained (by me) prometheus reporting.

	StatsForwardCount     Counter = nopCounter{}
	StatsStubForwardCount Counter = nopCounter{}
	StatsLookupCount      Counter = nopCounter{}
	StatsRequestCount     Counter = nopCounter{}
	StatsDnssecOkCount    Counter = nopCounter{}
	StatsNameErrorCount   Counter = nopCounter{}
	StatsNoDataCount      Counter = nopCounter{}

	StatsDnssecCacheMiss Counter = nopCounter{}
)
