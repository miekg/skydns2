// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"github.com/prometheus/client_golang/prometheus"
)

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
	// maintained (by me) Prometheus reporting.

	StatsForwardCount     Counter = nopCounter{}
	StatsStubForwardCount Counter = nopCounter{}
	StatsLookupCount      Counter = nopCounter{}
	StatsRequestCount     Counter = nopCounter{}
	StatsDnssecOkCount    Counter = nopCounter{}
	StatsNameErrorCount   Counter = nopCounter{}
	StatsNoDataCount      Counter = nopCounter{}

	StatsDnssecCacheMiss Counter = nopCounter{}
)

// Prometheus counters and gauges
var (
	PromForwardCount     prometheus.Counter
	PromStubForwardCount prometheus.Counter
	PromLookupCount      prometheus.Counter

	PromRequestCountTotal prometheus.Counter
	PromRequestCountTCP   prometheus.Counter
	PromRequestCountUDP   prometheus.Counter

	PromDnssecOkCount  prometheus.Counter
	PromNameErrorCount prometheus.Counter
	PromNoDataCount    prometheus.Counter
	PromRCacheSize     prometheus.Gauge
	PromSCacheSize     prometheus.Gauge
	PromRCacheMiss     prometheus.Counter
	PromSCacheMiss     prometheus.Counter
)
