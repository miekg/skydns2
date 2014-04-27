#SkyDNS [![Build Status](https://travis-ci.org/skynetservices/skydns.png)](https://travis-ci.org/skynetservices/skydns2)
*Version 2.0.0*

SkyDNS2 is a distributed service for announcement and discovery of services build on
top of [etcd](https://github.com/coreos/etcd). It utilizes DNS queries
to discover available services. This is done by leveraging SRV records in DNS,
with special meaning given to subdomains, priorities and weights.

This is the origingal [announcement blog post](http://blog.gopheracademy.com/skydns) for version 1, 
since then SkyDNS has seen some changes, most notably to ability to use etcd as a backend.

##Setup / Install
Compile SkyDNS, and execute it

`go get -d -v ./... && go build -v ./...`

SkyDNS' configuration is stored *in* etcd, there are no flags. To start SkyDNS set the
etcd machines in the variable ETCD_MACHINES:

    export ETCD_MACHINES='http://127.0.0.1:4001'
    ./skydns2

##API

### Configuration

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config -d value='{"dns_addr":"127.0.0.1:5354"}'

### Service Announcements
You announce your service by submitting JSON over HTTP to etcd with information about your service.
This information will then be available for queries either via DNS.

When providing information you will need to fill out the following values. Note you are free to use
whatever you like, so take the following list as a guide only.

* Host - The full name of your service, e.g., "rails.production.east.skydns.local", "web.staging.east.skydns.local", an IP address either v4 or v6.
* Port - the port where the service can be reached.
* Priority - the priority of the service.

Note some of these elements may be left out completely,
see the section named "Wildcards" below for more information.

#### Without Shared Secret 

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/b1 \
        -d value='{"Port":80,"Priority":10,"Host": "10.0.1.3"'}
    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/a1 \
        -d value='{"Port":80,"Priority":10,"Host": "web.google.nl"'}

#### With Shared Secret 

### Service Removal

### Retrieve Service Info via API

##Discovery (DNS)
You can find services by querying SkyDNS via any DNS client or utility. It uses a known domain syntax with wildcards to find matching services.

Priorities and Weights are based on the requested Region, as well as how many nodes are available matching the current request in the given region.

###Domain Format

#### Wildcards

In addition to only needing to specify as much of the domain as required for the granularity level you're looking for, you may also supply the wildcard `*` in any of the positions.

- east.*.*.production.skydns.local - Would return all services in the East region, that are a part of the production environment.

###Examples

Let's take a look at some results. First we need to add a few services so we have services to query against.

	// Service 1001 (East Region)
	curl -X PUT -L http://localhost:8080/skydns/services/1001 -d '{"Name":"TestService","Version":"1.0.0","Environment":"Production","Region":"East","Host":"web1.site.com","Port":80,"TTL":4000}'
	
	// Service 1002 (East Region)
	curl -X PUT -L http://localhost:8080/skydns/services/1002 -d '{"Name":"TestService","Version":"1.0.0","Environment":"Production","Region":"East","Host":"web2.site.com","Port":8080,"TTL":4000}'
	
	// Service 1003 (West Region)
	curl -X PUT -L http://localhost:8080/skydns/services/1003 -d '{"Name":"TestService","Version":"1.0.0","Environment":"Production","Region":"West","Host":"web3.site.com","Port":80,"TTL":4000}'
	
	// Service 1004 (West Region)
	curl -X PUT -L http://localhost:8080/skydns/services/1004 -d '{"Name":"TestService","Version":"1.0.0","Environment":"Production","Region":"West","Host":"web4.site.com","Port":80,"TTL":4000}'

Now we can try some of our example DNS lookups:

#####All services in the Production Environment
`dig @localhost production.skydns.local SRV`

	;; QUESTION SECTION:
	;production.skydns.local.			IN	SRV

	;; ANSWER SECTION:
	production.skydns.local.		629	IN	SRV	10 20 80   web1.site.com.
	production.skydns.local.		3979	IN	SRV	10 20 8080 web2.site.com.
	production.skydns.local.		3629	IN	SRV	10 20 9000 server24.
	production.skydns.local.		3985	IN	SRV	10 20 80   web3.site.com.
	production.skydns.local.		3990	IN	SRV	10 20 80   web4.site.com.

#####All TestService instances in Production Environment
`dig @localhost testservice.production.skydns.local SRV`

	;; QUESTION SECTION:
	;testservice.production.skydns.local.		IN	SRV

	;; ANSWER SECTION:
	testservice.production.skydns.local.	615		IN	SRV	10 20 80   web1.site.com.
	testservice.production.skydns.local.	3966	IN	SRV	10 20 8080 web2.site.com.
	testservice.production.skydns.local.	3615	IN	SRV	10 20 9000 server24.
	testservice.production.skydns.local.	3972	IN	SRV	10 20 80   web3.site.com.
	testservice.production.skydns.local.	3976	IN	SRV	10 20 80   web4.site.com.

#####All TestService v1.0.0 Instances in Production Environment
`dig @localhost 1-0-0.testservice.production.skydns.local SRV`

	;; QUESTION SECTION:
	;1-0-0.testservice.production.skydns.local.	IN	SRV

	;; ANSWER SECTION:
	1-0-0.testservice.production.skydns.local. 600  IN	SRV	10 20 80   web1.site.com.
	1-0-0.testservice.production.skydns.local. 3950 IN	SRV	10 20 8080 web2.site.com.
	1-0-0.testservice.production.skydns.local. 3600 IN	SRV	10 20 9000 server24.
	1-0-0.testservice.production.skydns.local. 3956 IN	SRV	10 20 80   web3.site.com.
	1-0-0.testservice.production.skydns.local. 3961 IN	SRV	10 20 80   web4.site.com.

#####All TestService Instances at any version, within the East region
`dig @localhost east.*.testservice.production.skydns.local SRV`

This is where we've changed things up a bit, notice we used the "*" wildcard for
version so we get any version, and because we've supplied an explicit region
that we're looking for we get that as the highest DNS priority, with the weight
being distributed evenly, then all of our West instances still show up for
fail-over, but with a higher Priority.

	;; QUESTION SECTION:
	;east.*.testservice.production.skydns.local. IN	SRV

	;; ANSWER SECTION:
	east.*.testservice.production.skydns.local. 531  IN SRV	10 50 80   web1.site.com.
	east.*.testservice.production.skydns.local. 3881 IN SRV	10 50 8080 web2.site.com.
	east.*.testservice.production.skydns.local. 3531 IN SRV	20 33 9000 server24.
	east.*.testservice.production.skydns.local. 3887 IN SRV	20 33 80   web3.site.com.
	east.*.testservice.production.skydns.local. 3892 IN SRV	20 33 80   web4.site.com.


####A Records
To return A records, simply run a normal DNS query for a service matching the above patterns.

Let's add some web servers to SkyDNS:

	curl -X PUT -L http://localhost:8080/skydns/services/1011 -d '{"Name":"rails","Version":"1.0.0","Environment":"Production","Region":"East","Host":"127.0.0.10","Port":80,"TTL":400000}'
	curl -X PUT -L http://localhost:8080/skydns/services/1012 -d '{"Name":"rails","Version":"1.0.0","Environment":"Production","Region":"East","Host":"127.0.0.11","Port":80,"TTL":400000}'
	curl -X PUT -L http://localhost:8080/skydns/services/1013 -d '{"Name":"rails","Version":"1.0.0","Environment":"Production","Region":"West","Host":"127.0.0.12","Port":80,"TTL":400000}'
	curl -X PUT -L http://localhost:8080/skydns/services/1014 -d '{"Name":"rails","Version":"1.0.0","Environment":"Production","Region":"West","Host":"127.0.0.13","Port":80,"TTL":400000}'

Now do a normal DNS query:
`dig rails.production.skydns.local`

	;; QUESTION SECTION:
	;rails.production.skydns.local.	IN	A

	;; ANSWER SECTION:
	rails.production.skydns.local. 399918 IN A	127.0.0.10
	rails.production.skydns.local. 399918 IN A	127.0.0.11
	rails.production.skydns.local. 399918 IN A	127.0.0.12
	rails.production.skydns.local. 399919 IN A	127.0.0.13

Now you have a list of all known IP Addresses registered running the `rails`
service name. Because we're returning A records and not SRV records, there
are no ports listed, so this is only useful when you're querying for services
running on ports known to you in advance. Notice, we didn't specify version or
region, but we could have.

####DNS Forwarding

By specifying `-nameserver="8.8.8.8:53,8.8.4.4:53` on the `skydns` command line,
you create a DNS forwarding proxy. In this case it round robins between the two
nameserver IPs mentioned on the command line.

Requests for which SkyDNS isn't authoritative
will be forwarded and proxied back to the client. This means that you can set
SkyDNS as the primary DNS server in `/etc/resolv.conf` and use it for both service
discovery and normal DNS operations.

*Please test this before relying on it in production, as there may be edge cases that don't work as planned.*

####DNSSEC

SkyDNS support signing DNS answers (also know as DNSSEC). To use it you need to
create a DNSSEC keypair and use that in SkyDNS. For instance if the domain for
SkyDNS is `skydns.local`:

    dnssec-keygen skydns.local
    Generating key pair............++++++ ...................................++++++
    Kskydns.local.+005+49860

This creates two files both with the basename `Kskydns.local.+005.49860`, one of the
extension `.key` (this holds the public key) and one with the extension `.private` which
hold the private key. The basename of this file should be given to SkyDNS's -dnssec
option: `-dnssec=Kskydns.local.+005+49860`

If you then query with `dig +dnssec` you will get signatures, keys and nsec records returned.

## License
The MIT License (MIT)

Copyright © 2014 The SkyDNS Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
