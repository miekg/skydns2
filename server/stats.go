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
	promDnssecOkCount    prometheus.Counter
	promRequestCount     *prometheus.CounterVec
	promErrorCount       *prometheus.CounterVec
	promCacheSize        *prometheus.GaugeVec
	promCacheMiss        *prometheus.CounterVec
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
	}, []string{"type"}) // total, udp, tcp
	prometheus.MustRegister(promRequestCount)

	promDnssecOkCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_dnssec_ok_count",
		Help:      "Counter of DNSSEC requests.",
	})

	promErrorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_error_count",
		Help:      "Counter of DNS requests resulting in an error.",
	}, []string{"error"}) // nxdomain, nodata, truncated
	prometheus.MustRegister(promErrorCount)

	// Caches
	promCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "cache_total_size",
		Help:      "The total size of all elements in the cache.",
	}, []string{"type"}) // rr, sig
	prometheus.MustRegister(promCacheSize)

	promCacheMiss = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_cache_miss_count",
		Help:      "Counter of DNS requests that result in a cache miss.",
	}, []string{"type"}) //rr, sig
	prometheus.MustRegister(promCacheMiss)

	prometheus.MustRegister(promForwardCount)
	prometheus.MustRegister(promStubForwardCount)
	prometheus.MustRegister(promLookupCount)
	prometheus.MustRegister(promDnssecOkCount)

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
