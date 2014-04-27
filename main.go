// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"log"
	"os"
	"strings"

	"github.com/coreos/go-etcd/etcd"
)

var machines = strings.Split(os.Getenv("ETCD_MACHINES"), ",")

func newClient() *etcd.Client {
	client := etcd.NewClient(machines)
	client.SyncCluster()
	return client
}

func main() {
	client := newClient()

	config, err := LoadConfig(client)
	if err != nil {
		log.Fatal(err)
	}
	s := NewServer(config, client)

	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}
