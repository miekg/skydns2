// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/influxdb"
	"github.com/rcrowley/go-metrics/stathat"
	"net"
)

var (
	StatsForwardCount   metrics.Counter
	StatsRequestCount   metrics.Counter
	StatsDnssecOkCount  metrics.Counter
	StatsDnssecCacheMiss  metrics.Counter
	StatsNameErrorCount metrics.Counter
	StatsNoDataCount    metrics.Counter

	graphiteServer, stathatUser string
	influxConfig                *influxdb.Config
)

func init() {
	influxConfig = &influxdb.Config{}

	//	TODO(miek): env vars
	// GRAPHITE_SERVER
	//	flag.StringVar(&graphiteServer, "graphiteServer", "", "Graphite Server connection string e.g. 127.0.0.1:2003")
	// STATHAT_USER
	//	flag.StringVar(&stathatUser, "stathatUser", "", "StatHat account for metrics")
	// INFLUX_SERVER
	//	flag.StringVar(&influxConfig.Host, "influxdbHost", "", "Influxdb host address for metrics")
	// INFLUX_DATABASE
	//	flag.StringVar(&influxConfig.Database, "influxdbDatabase", "", "Influxdb database name for metrics")
	// INFLUX_USER
	//	flag.StringVar(&influxConfig.Username, "influxdbUsername", "", "Influxdb username for metrics")
	// INFLUX_PASSWORD
	//	flag.StringVar(&influxConfig.Password, "influxdbPassword", "", "Influxdb password for metrics")

	StatsForwardCount = metrics.NewCounter()
	metrics.Register("skydns-forward-requests", StatsForwardCount)

	StatsDnssecOkCount = metrics.NewCounter()
	metrics.Register("skydns-dnssecok-requests", StatsDnssecOkCount)

	StatsDnssecCacheMiss = metrics.NewCounter()
	metrics.Register("skydns-dnssec-cache-miss", StatsDnssecCacheMiss)

	StatsRequestCount = metrics.NewCounter()
	metrics.Register("skydns-requests", StatsRequestCount)

	StatsNameErrorCount = metrics.NewCounter()
	metrics.Register("skydns-nameerror-responses", StatsNameErrorCount)

	StatsNoDataCount = metrics.NewCounter()
	metrics.Register("skydns-nodata-responses", StatsNoDataCount)
}

func Collect() {
	if len(graphiteServer) > 1 {
		addr, err := net.ResolveTCPAddr("tcp", graphiteServer)
		if err != nil {
			go metrics.Graphite(metrics.DefaultRegistry, 10e9, "skydns", addr)
		}
	}

	if len(stathatUser) > 1 {
		go stathat.Stathat(metrics.DefaultRegistry, 10e9, stathatUser)
	}

	if influxConfig.Host != "" {
		go influxdb.Influxdb(metrics.DefaultRegistry, 10e9, influxConfig)
	}
}
