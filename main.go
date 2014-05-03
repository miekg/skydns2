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
	machines = os.Getenv("ETCD_MACHINES") // List of URLs to etcd
	tlskey   = os.Getenv("ETCD_TLSKEY")   // TLS private key path
	tlspem   = os.Getenv("ETCD_TLSPEM")   // X509 certificate
)

func newClient() (client *etcd.Client) {
	var etcdHosts []string
	if machines == "" {
		etcdHosts = []string{"http://127.0.0.1:4001"}
	} else {
		etcdHosts = strings.Split(machines, ",")
	}
	log.Println("Connecting to etcd cluster at", etcdHosts)
	if strings.HasPrefix(etcdHosts[0], "https://") {
		var err error
		if client, err = etcd.NewTLSClient(etcdHosts, tlspem, tlskey, ""); err != nil {
			log.Fatal(err)
		}
	} else {
		client = etcd.NewClient(etcdHosts)
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
