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
	PrometheusPort      = os.Getenv("PROMETHEUS_PORT")
	PrometheusPath      = os.Getenv("PROMETHEUS_PATH")
	PrometheusNamespace = os.Getenv("PROMETHEUS_NAMESPACE")
	PrometheusSubsystem = os.Getenv("PROMETHEUS_SUBSYSTEM")
)

func init() {
	println("init")
	if PrometheusPath == "" {
		PrometheusPath = "/metrics"
	}
	if PrometheusNamespace == "" {
		PrometheusNamespace = "skydns"
	}

	server.PromForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_forward_count",
		Help:      "Counter of DNS requests forwarded.",
	})

	server.PromStubForwardCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_stub_forward_count",
		Help:      "Counter of DNS requests forwarded to stubs.",
	})

	// convert to VEC and use labels
	server.PromLookupCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_lookup_count",
		Help:      "Counter of DNS lookups performed.",
	})

	server.PromRequestCountTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_request_count",
		Help:      "Counter of total DNS requests made.",
	})

	server.PromRequestCountTCP = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_request_count_tcp",
		Help:      "Counter of DNS requests made via TCP.",
	})

	server.PromRequestCountUDP = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_request_count_udp",
		Help:      "Counter of DNS requests made via UDP.",
	})

	server.PromDnssecOkCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_dnssec_ok_count",
		Help:      "Counter of DNSSEC requests.",
	})

	server.PromNameErrorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_name_error_count",
		Help:      "Counter of DNS requests resulting in a name error.",
	})

	server.PromNoDataCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_no_data_count",
		Help:      "Counter of DNS requests that contained no data.",
	})

	// Caches
	server.PromRCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "rcache_total_size",
		Help:      "The total size of all DNS messages in the rcache.",
	})
	server.PromSCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "scache_total_size",
		Help:      "The total size of all RRSIGs in the scache.",
	})

	server.PromRCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_rcache_miss_count",
		Help:      "Counter of DNS requests that result in cache miss.",
	})
	server.PromSCacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: PrometheusNamespace,
		Subsystem: PrometheusSubsystem,
		Name:      "dns_scache_miss_count",
		Help:      "Counter of signature requests that result in cache miss.",
	})

	prometheus.MustRegister(server.PromForwardCount)
	prometheus.MustRegister(server.PromStubForwardCount)
	prometheus.MustRegister(server.PromLookupCount)
	prometheus.MustRegister(server.PromRequestCountTotal)
	prometheus.MustRegister(server.PromRequestCountTCP)
	prometheus.MustRegister(server.PromRequestCountUDP)
	prometheus.MustRegister(server.PromDnssecOkCount)
	prometheus.MustRegister(server.PromNameErrorCount)
	prometheus.MustRegister(server.PromNoDataCount)
	prometheus.MustRegister(server.PromRCacheSize)
	prometheus.MustRegister(server.PromSCacheSize)
	prometheus.MustRegister(server.PromRCacheMiss)
	prometheus.MustRegister(server.PromSCacheMiss)
}

func Metrics() {
	if PrometheusPort == "" {
		return
	}
	_, err := strconv.Atoi(PrometheusPort)
	if err != nil {
		log.Printf("skydns: PROMETHEUS_PORT is not a number: %s, not enabling metrics", PrometheusPort)
		return
	}

	http.Handle(PrometheusPath, prometheus.Handler())
	go func() {
		log.Fatalf("skydns: %s", http.ListenAndServe(":"+PrometheusPort, nil))
	}()
	log.Printf("skydns: metrics enabled")
}
