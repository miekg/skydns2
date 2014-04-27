// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

type Service struct {
	// This *is* the rdata from a SRV record, but with a twist.
	// Host (Target in SRV) must be a domain name, but if it looks like an IP
	// address (4/6), we will treat it like an IP address.

	Priority int
	//	Weight   int // Don't let the API set weights, we will do this automatically.
	Port int
	Host string

	ttl uint32
	key string
}
