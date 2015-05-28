// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package stats

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/skynetservices/skydns/server"
)

var (
	prometheusPort      = os.Getenv("PROMETHEUS_PORT")
	prometheusPath      = os.Getenv("PROMETHEUS_PATH")
	prometheusNamespace = os.Getenv("PROMETHEUS_NAMESPACE")
	prometheusSubsystem = os.Getenv("PROMETHEUS_SUBSYSTEM")
)

func init() {
	if prometheusPath == "" {
		prometheusPath = "/metrics"
	}
	if prometheusNamespace == "" {
		prometheusNamespace = "skydns"
	}

	server.PromForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_forward_count",
		Help:      "Counter of DNS requests forwarded.",
	})

	server.PromStubForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_stub_forward_count",
		Help:      "Counter of DNS requests forwarded to stubs.",
	})

	server.PromLookupCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_lookup_count",
		Help:      "Counter of DNS lookups performed.",
	})

	server.PromRequestCountTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_request_count",
		Help:      "Counter of total DNS requests made.",
	})

	server.PromRequestCountTCP = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_request_count_tcp",
		Help:      "Counter of DNS requests made via TCP.",
	})

	server.PromRequestCountUDP = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_request_count",
		Help:      "Counter of DNS requests made via UDP.",
	})

	server.PromDnssecOkCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_dnssec_ok_count",
		Help:      "Counter of DNSSEC requests.",
	})

	server.PromNameErrorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_name_error_count",
		Help:      "Counter of DNS requests resulting in a name error.",
	})

	server.PromNoDataCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_no_data_count",
		Help:      "Counter of DNS requests that contained no data.",
	})

	// Caches
	server.PromRCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "rcache_total_size",
		Help:      "The total size of all RRs in the rcache.",
	})
	server.PromSCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "scache_total_size",
		Help:      "The total size of all RRSIGs in the scache.",
	})

	server.PromRCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_rcache_miss_count",
		Help:      "Counter of DNS requests that result in cache miss.",
	})
	server.PromSCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Subsystem: prometheusSubsystem,
		Name:      "dns_scache_miss_count",
		Help:      "Counter of signature requests that result in cache miss.",
	})

	prometheus.MustRegister(server.PromForwardCount)
	prometheus.MustRegister(server.PromStubForwardCount)
	prometheus.MustRegister(server.PromLookupCount)
	prometheus.MustRegister(server.PromRequestCount)
	prometheus.MustRegister(server.PromDnssecOkCount)
	prometheus.MustRegister(server.PromNameErrorCount)
	prometheus.MustRegister(server.PromNoDataCount)
	prometheus.MustRegister(server.PromRCacheSize)
	prometheus.MustRegister(server.PromSCacheSize)
	prometheus.MustRegister(server.PromRCacheMiss)
	prometheus.MustRegister(server.PromSCacheMiss)
}

func Metrics() {
	if prometheusPort == "" {
		return
	}
	_, err := strconv.Atoi(prometheusPort)
	if err != nil {
		log.Printf("skydns: PROMETHEUS_PORT is not a number: %s, not enabling metrics", prometheusPort)
		return
	}

	http.Handle(prometheusPath, prometheus.Handler())
	go func() {
		log.Fatalf("skydns: %s", http.ListenAndServe(":"+prometheusPort, nil))
	}()
	log.Printf("skydns: metrics enabled")
}
