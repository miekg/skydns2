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

var (
	machines = strings.Split(os.Getenv("ETCD_MACHINES"), ",") // List of URLs to etcd
	tlskey   = os.Getenv("ETCD_TLSKEY")                       // TLS private key path
	tlspem   = os.Getenv("ETCD_TLSPEM")                       // X509 certificate
)

func newClient() (client *etcd.Client) {
	if len(machines) == 1 && machines[0] == "" {
		machines[0] = "http://127.0.0.1:4001"
	}
	if strings.HasPrefix(machines[0], "https://") {
		var err error
		if client, err = etcd.NewTLSClient(machines, tlspem, tlskey, ""); err != nil {
			log.Fatal(err)
		}
	} else {
		client = etcd.NewClient(machines)
	}
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
