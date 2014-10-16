package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"time"

	"encoding/json"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	pconfig "github.com/GoogleCloudPlatform/kubernetes/pkg/proxy/config"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	"github.com/coreos/go-etcd/etcd"
	"github.com/skynetservices/skydns/msg"
)

// The periodic interval for checking the state of things.
const syncInterval = 5 * time.Second

type KubernetesSync struct {
	mu         sync.Mutex // protects serviceMap
	serviceMap map[string]*serviceInfo
	eclient    *etcd.Client
}

func NewKubernetesSync(client *etcd.Client) *KubernetesSync {
	ks := &KubernetesSync{
		serviceMap: make(map[string]*serviceInfo),
		eclient:    client,
	}
	return ks
}

// This is a belt-and-suspenders loop that periodically
// addes the records in the local cache of Kubernetes
// services to the skydns repository to prevent them
// from expiring.
func (ksync *KubernetesSync) SyncLoop() {
	for {
		select {
		case <-time.After(syncInterval):
			log.Println("periodic sync")
			ksync.ensureDNS()
		}
	}
}

// Ensure that dns records exist for all services.
// This seems a bit redundant. TBD - remove?
func (ksync *KubernetesSync) ensureDNS() {
	ksync.mu.Lock()
	defer ksync.mu.Unlock()
	for name, info := range ksync.serviceMap {
		err := ksync.addDNS(name, info)
		if err != nil {
			log.Println("failed to ensure dns for %q: %s", name, err)
		}
	}
}

// OnUpdate manages the active set of service records.
// Active service records get ttl bumps if found in the update set or
// removed if missing from the update set.
func (ksync *KubernetesSync) OnUpdate(services []api.Service) {
	activeServices := util.StringSet{}
	for _, service := range services {
		activeServices.Insert(service.ID)
		info, exists := ksync.getServiceInfo(service.ID)
		serviceIP := net.ParseIP(service.PortalIP)
		if exists && (info.portalPort != service.Port || !info.portalIP.Equal(serviceIP)) {
			err := ksync.removeDNS(service.ID, info)
			if err != nil {
				log.Printf("failed to remove dns for %q: %s\n", service.ID, err)
			}
		}
		log.Printf("adding new service %q at %s:%d/%s (local :%d)\n", service.ID, serviceIP, service.Port, service.Protocol, service.ProxyPort)
		si := &serviceInfo{
			proxyPort: service.ProxyPort,
			protocol:  service.Protocol,
			active:    true,
		}
		ksync.setServiceInfo(service.ID, si)
		si.portalIP = serviceIP
		si.portalPort = service.Port
		err := ksync.addDNS(service.ID, si)
		if err != nil {
			log.Println("failed to add dns %q: %s", service.ID, err)
		}
	}
	ksync.mu.Lock()
	defer ksync.mu.Unlock()
	for name, info := range ksync.serviceMap {
		if !activeServices.Has(name) {
			err := ksync.removeDNS(name, info)
			if err != nil {
				log.Println("failed to remove dns for %q: %s", name, err)
			}
			delete(ksync.serviceMap, name)
		}
	}
}

func (ksync *KubernetesSync) getServiceInfo(service string) (*serviceInfo, bool) {
	ksync.mu.Lock()
	defer ksync.mu.Unlock()
	info, ok := ksync.serviceMap[service]
	return info, ok
}

func (ksync *KubernetesSync) setServiceInfo(service string, info *serviceInfo) {
	ksync.mu.Lock()
	defer ksync.mu.Unlock()
	ksync.serviceMap[service] = info
}

func (ksync *KubernetesSync) removeDNS(service string, info *serviceInfo) error {
	record := service + "." + config.Domain
	// Remove from SkyDNS registration
	log.Printf("removing %s from DNS", record)
	_, err := ksync.eclient.Delete(msg.Path(record), true)
	return err
}

func (ksync *KubernetesSync) addDNS(service string, info *serviceInfo) error {
	// ADD to SkyDNS registry
	svc := msg.Service{
		Host:     info.portalIP.String(),
		Port:     info.portalPort,
		Priority: 10,
		Weight:   10,
		Ttl:      30,
	}
	b, err := json.Marshal(svc)
	record := service + "." + config.Domain
	//Set with no TTL, and hope that kubernetes events are accurate.
	//TODO(BJK) Think this through a little more

	log.Printf("setting dns record: %v\n", record)
	_, err = ksync.eclient.Set(msg.Path(record), string(b), uint64(0))
	return err
}

type serviceInfo struct {
	portalIP   net.IP
	portalPort int
	protocol   api.Protocol
	proxyPort  int
	mu         sync.Mutex // protects active
	active     bool
}

func init() {
	client.BindClientConfigFlags(flag.CommandLine, clientConfig)
}

func WatchKubernetes(eclient *etcd.Client) {
	serviceConfig := pconfig.NewServiceConfig()
	endpointsConfig := pconfig.NewEndpointsConfig()

	// define api config source
	if clientConfig.Host != "" {
		log.Println("using api calls to get Kubernetes config %v", clientConfig.Host)
		client, err := client.New(clientConfig)
		if err != nil {
			log.Fatalf("Kubernetes requested, but received invalid API configuration: %v", err)
		}
		pconfig.NewSourceAPI(
			client,
			30*time.Second,
			serviceConfig.Channel("api"),
			endpointsConfig.Channel("api"),
		)
	}
	ks := NewKubernetesSync(eclient)
	// Wire skydns to handle changes to services
	serviceConfig.RegisterHandler(ks)
	ks.SyncLoop()
}
