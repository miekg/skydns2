// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

/*
SKYDNS

SkyDNS is a distributed service for announcement and discovery of services built on
top of Ectd (https://github.com/coreos/etcd). It utilizes DNS queries
to discover available services. This is done by leveraging SRV records in DNS,
with special meaning given to subdomains, priorities and weights.

SkyDNS' configuration is stored in etcd: there are no flags. To start SkyDNS, set the
etcd machines with the environment variable ETCD_MACHINES:

    export ETCD_MACHINES='http://192.168.0.1:4001,http://192.168.0.2:4001'
    ./skydns

If `ETCD_MACHINES` is not set, SkyDNS will default to using `http://127.0.0.1:4001` to connect to etcd.

The configuration is stored in etcd under the key `/skydns/config`. The following parameters
may be set:

* `dns_addr`: IP:port on which SkyDNS should listen, defaults to `127.0.0.1:53`.

* `domain`: domain for which SkyDNS is authoritative, defaults to `skydns.local.`.

* `round_robin`: enable round-robin sorting for A and AAAA responses, defaults to true.

* `nameservers`: forward DNS requests to these nameservers (IP:port combination), when not authoritative for a domain.

* `read_timeout`: network read timeout, for DNS and talking with etcd.

* `ttl`: default TTL in seconds to use on replies when none is set in etcd, defaults to 3600.

* `min_ttl`: minimum TTL in seconds to use on NXDOMAIN, defaults to 30.

* `dnssec`: enable DNSSEC.

To set the configuration, use something like:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config \
        -d value='{"dns_addr":"127.0.0.1:5354","ttl":3600}'

SkyDNS needs to be restarted for configuration changes to take effect.

SkyDNS uses these environment variables:

TODO(miek): list them here

Announce your service by submitting JSON over HTTP to etcd with information about your service.
This information will then be available for queries via DNS.
We use the directory `/skydns` to anchor all names.

When providing information you will need to fill out the following values.

* Path - The path of the key in etcd, e.g. if the domain you want to register is "rails.production.east.skydns.local", you need to reverse it and replace the dots with slashes. So the name here becomes: local/skydns/east/production/rails.
  Then prefix the `/skydns/` string too, so the final path becomes `/v2/keys/skdydns/local/skydns/east/production/rails`

* Host - The name of your service, e.g., `service5.mydomain.com`,  and IP address (either v4 or v6)

* Port - the port where the service can be reached.

* Priority - the priority of the service.

Adding the service can thus be done with:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/production/rails \
        -d value='{"host":"service5.example.com","priority":20}'

Or with etcdctl (https://github.com/coreos/etcdctl):

    etcdctl set /skydns/local/skydns/east/production/rails \
        '{"host":"service5.example.com","priority":20}'

When querying the DNS for services you can use wildcards or query for subdomains
You can find services by querying SkyDNS via any DNS client or utility.

Testing one of the names with `dig`:

    % dig @localhost SRV 1.rails.production.east.skydns.local
    ;; QUESTION SECTION:
    ;1.rails.production.east.skydns.local.	IN	SRV

    ;; ANSWER SECTION:
    1.rails.production.east.skydns.local. 3600 IN SRV 10 0 8080 service1.example.com.

Of course using the full names isn't *that* useful, so SkyDNS lets you query
for subdomains, and returns responses based upon the amount of services matched
by the subdomain or from the the wildcard query. If we are interested in all
the servers in the `east` region, we simply omit the rightmost labels from our
query:

    % dig @localhost SRV east.skydns.local
    ;; QUESTION SECTION
    ; east.skydns.local.    IN      SRV

    ;; ANSWER SECTION:
    east.skydns.local.      3600    IN      SRV     10 20 8080 service1.example.com.
    east.skydns.local.      3600    IN      SRV     10 20 8080 4.rails.staging.east.skydns.local.
    east.skydns.local.      3600    IN      SRV     10 20 8080 6.rails.staging.east.skydns.local.

    ;; ADDITIONAL SECTION:
    4.rails.staging.east.skydns.local. 3600 IN A    10.0.1.125
    6.rails.staging.east.skydns.local. 3600 IN AAAA 2003::8:1

Here three entries of the `east` are returned.

There is one other feature at play here. The second and third names,
`{4,6}.rails.staging.east.skydns.local`, only had an IP record configured. Here
SkyDNS used the ectd path to construct a target name and then puts the actual
IP address in the additional section. Directly querying for the A records of
`4.rails.staging.east.skydns.local.` of course also works:

    % dig @localhost -p 5354 +noall +answer A 4.rails.staging.east.skydns.local.
    4.rails.staging.east.skydns.local. 3600 IN A    10.0.1.125

SkyDNS will internally synthesis name which will be used for NS records. The first
nameserver used will be named `ns1.dns.skydns.local` in the default setup . Extra
nameserver will be numbered ns2, ns3, etc. The subdomain `dns.skydns.local` will take
precedence over services with a similar name.

By specifying nameservers in SkyDNS's config, for instance `8.8.8.8:53,8.8.4.4:53`,
you create a DNS forwarding proxy. In this case it round-robins between the two
nameserver IPs mentioned.

Requests for which SkyDNS isn't authoritative will be forwarded and proxied back to
the client. This means that you can set SkyDNS as the primary DNS server in
`/etc/resolv.conf` and use it for both service discovery and normal DNS operations.

SkyDNS support signing DNS answers (also know as DNSSEC). To use it you need to
create a DNSSEC keypair and use that in SkyDNS. For instance if the domain for
SkyDNS is `skydns.local`:

    % dnssec-keygen skydns.local
    Generating key pair............++++++ ...................................++++++
    Kskydns.local.+005+49860

This creates two files both with the basename `Kskydns.local.+005.49860`, one of the
extension `.key` (this holds the public key) and one with the extension `.private` which
hold the private key. The basename of this file should be given to SkyDNS's DNSSEC configuration
option: `Kskydns.local.+005+49860`, like so (together with some other options):

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config -d \
        value='{"dns_addr":"127.0.0.1:5354","dnssec":"Kskydns.local.+005+55656"}'

If you then query with `dig +dnssec` you will get signatures, keys and NSEC3 records returned.
Authenticated denial of existence is implemented using NSEC3 whitelies,
see RFC7129 (http://tools.ietf.org/html/rfc7129), Appendix B.
*/
package main
