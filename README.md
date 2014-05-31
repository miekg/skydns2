# SkyDNS [![Build Status](https://travis-ci.org/skynetservices/skydns.png)](https://travis-ci.org/skynetservices/skydns)
*Version 2.0.0*

SkyDNS is a distributed service for announcement and discovery of services built on
top of [etcd](https://github.com/coreos/etcd). It utilizes DNS queries
to discover available services. This is done by leveraging SRV records in DNS,
with special meaning given to subdomains, priorities and weights.

This is the original [announcement blog post](http://blog.gopheracademy.com/skydns) for version 1. 
Since then, SkyDNS has seen some changes, most notably the ability to use etcd as a backend.

# Changes since version 1

SkyDNS2:

* Does away with Raft and uses Etcd (which uses raft).
* Makes is possible to query arbitrary domain names.
* Is a thin layer above etcd, that translates etcd keys and values to the DNS.
    In the near future, SkyDNS2 will possibly be upstreamed and incorperated directly in etcd.
* Does DNSSEC with NSEC3 instead of NSEC (Work in progress).

Note thats bugs in SkyDNS1 will still be fixed, but the main development effort will be focussed on version 2.
[Version 1 of SkyDNS can be found here](https://github.com/skynetservices/skydns1).

# Future ideas

* Abstract away the backend in an interface, so different backends can be used.
* Make SkyDNS a library and provide a small server.
 
## Setup / Install
Download/compile and run etcd. See the documentation for etcd at <https://github.com/coreos/etcd>.

Then compile SkyDNS:

`go get -d -v ./... && go build -v ./...`

SkyDNS' configuration is stored *in* etcd: but there are also flags. To start SkyDNS, set the
etcd machines with the environment variable ETCD_MACHINES:

    export ETCD_MACHINES='http://192.168.0.1:4001,http://192.168.0.2:4001'
    ./skydns

If `ETCD_MACHINES` is not set, SkyDNS will default to using `http://127.0.0.1:4001` to connect to etcd.
Or you can use the flag `-machines`.

## Configuration
SkyDNS' configuration is stored in etcd as a JSON object under the key `/skydns/config`. The following parameters
may be set:

* `dns_addr`: IP:port on which SkyDNS should listen, defaults to `127.0.0.1:53`.
* `domain`: domain for which SkyDNS is authoritative, defaults to `skydns.local.`.
* `dnssec`: enable DNSSEC (broken at the moment).
* `round_robin`: enable round-robin sorting for A and AAAA responses, defaults to true.
* `nameservers`: forward DNS requests to these nameservers (array of IP:port combination), when not
    authoritative for a domain.
* `read_timeout`: network read timeout, for DNS and talking with etcd.
* `ttl`: default TTL in seconds to use on replies when none is set in etcd, defaults to 3600.
* `min_ttl`: minimum TTL in seconds to use on NXDOMAIN, defaults to 30.

To set the configuration, use something like:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config \
        -d value='{"dns_addr":"127.0.0.1:5354","ttl":3600, "nameservers": ["8.8.8.8:53","8.8.4.4:53"]}'

SkyDNS needs to be restarted for configuration changes to take effect. This might change, so that SkyDNS
can re-read the config from Etcd after a HUP signal.

### Environment Variables

SkyDNS uses these environment variables:

* `ETCD_MACHINES` - list of etcd machines, "http://localhost:4001,http://etcd.example.com:4001".
* `ETCD_TLSKEY` - TLS private key path.
* `ETCD_TLSPEM` - X509 certificate path.

And these are used for statistics:

* `GRAPHITE_SERVER`
* `STATHAT_USER`
* `INFLUX_SERVER`
* `INFLUX_DATABASE`
* `INFLUX_USER`
* `INFLUX_PASSWORD`

## Service Announcements
Announce your service by submitting JSON over HTTP to etcd with information about your service.
This information will then be available for queries via DNS.
We use the directory `/skydns` to anchor all names.

When providing information you will need to fill out (some of) the following values.

* Path - The path of the key in etcd, e.g. if the domain you want to register is "rails.production.east.skydns.local", you need to reverse it and replace the dots with slashes. So the name here becomes:
    `local/skydns/east/production/rails`. 
  Then prefix the `/skydns/` string too, so the final path becomes
    `/v2/keys/skdydns/local/skydns/east/production/rails`
* Host - The name of your service, e.g., `service5.mydomain.com`,  and IP address (either v4 or v6)
* Port - the port where the service can be reached.
* Priority - the priority of the service, the lower the value, the more preferred;
* Weight - a weight factor that will be used for services with the same Priority.
* TTL - the time-to-live of the service, overriding the default TTL. If the etcd key also has a TTL, the minimum of this value and the etcd TTL is used.

Path and Host are mandatory.

Adding the service can thus be done with:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/production/rails \
        -d value='{"host":"service5.example.com","priority":20}'

Or with [`etcdctl`](https://github.com/coreos/etcdctl):

    etcdctl set /skydns/local/skydns/east/production/rails \
        '{"host":"service5.example.com","priority":20}'

When querying the DNS for services you can use wildcards or query for subdomains. See the section named "Wildcards" below for more information.

The Weight of a service is calculated as follows. We treat Weight as a percentage, so if there are
3 services, the weight is set to 33 for each:

| Service | Weight  | SRV.Weight |
| --------| ------- | ---------- |
|    a    |   100   |    33      |
|    b    |   100   |    33      |
|    c    |   100   |    33      |

If we add other weights to the equation some services will get a different Weight:

| Service | Weight  | SRV.Weight |
| --------| ------- | ---------- |
|    a    |   120   |    34      |
|    b    |   100   |    28      |
|    c    |   130   |    37      |

Note, all calculations are rounded down, so the sum total might be lower than 100.

## Service Discovery via the DNS

You can find services by querying SkyDNS via any DNS client or utility. It uses a known domain syntax with subdomains to find matching services.

For the purpose of this document, let's suppose we have added the following services to etcd:

* 1.rails.production.east.skydns.local, mapping to service1.example.com
* 2.rails.production.west.skydns.local, mapping to service2.example.com
* 4.rails.staging.east.skydns.local, mapping to 10.0.1.125
* 6.rails.staging.east.skydns.local, mapping to 2003::8:1

These names can be added with:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/production/rails/1 \
        -d value='{"host":"service1.example.com","port":8080}'
    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/west/production/rails/2 \
        -d value='{"host":"service2.example.com","port":8080}'
    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/staging/rails/4 \
        -d value='{"host":"10.0.1.125","port":8080}'
    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/staging/rails/6 \
        -d value='{"host":"2003::8:1","port":8080}'

Testing one of the names with `dig`:

    % dig @localhost SRV 1.rails.production.east.skydns.local
    ;; QUESTION SECTION:
    ;1.rails.production.east.skydns.local.	IN	SRV

    ;; ANSWER SECTION:
    1.rails.production.east.skydns.local. 3600 IN SRV 10 0 8080 service1.example.com.

### Wildcards

Of course using the full names isn't *that* useful, so SkyDNS lets you query for subdomains, and returns responses based upon the amount of services matched by the subdomain or from the wildcard query.

If we are interested in all the servers in the `east` region, we simply omit the rightmost labels from our query:

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

Here all three entries of the `east` are returned. 

There is one other feature at play here. The second and third names, `{4,6}.rails.staging.east.skydns.local`, only had an IP record configured. Here SkyDNS used the ectd path to construct a target name and then puts the actual IP address in the additional section. Directly querying for the A records of `4.rails.staging.east.skydns.local.` of course also works:

    % dig @localhost -p 5354 +noall +answer A 4.rails.staging.east.skydns.local.
    4.rails.staging.east.skydns.local. 3600 IN A    10.0.1.125

Another way to leads to the same result it to query for `*.east.skydns.local`, you even put the wildcard
(the `*`) in the middle of a name `staging.*.skydns.local` is a valid query, which returns all name
in staging, regardless of the region. Multiple wildcards per name are also permitted.

### Examples

Now we can try some of our example DNS lookups:

#### SRV Records

Get all Services in staging.east:

    % dig @localhost staging.east.skydns.local. SRV

    ;; QUESTION SECTION:
    ;staging.east.skydns.local. IN  SRV

    ;; ANSWER SECTION:
    staging.east.skydns.local. 3600 IN  SRV 10 50 8080 4.rails.staging.east.skydns.local.
    staging.east.skydns.local. 3600 IN  SRV 10 50 8080 6.rails.staging.east.skydns.local.

    ;; ADDITIONAL SECTION:
    4.rails.staging.east.skydns.local. 3600 IN A    10.0.1.125
    6.rails.staging.east.skydns.local. 3600 IN AAAA 2003::8:1

#### A/AAAA Records
To return A records, simply run a normal DNS query for a service matching the above patterns.

Now do a normal DNS query:

    % dig @localhost staging.east.skydns.local. A

    ;; QUESTION SECTION:
    ;staging.east.skydns.local. IN  A

    ;; ANSWER SECTION:
    staging.east.skydns.local. 3600 IN  A   10.0.1.125

Now you have a list of all known IP Addresses registered running in staging in
the east area.

Because we're returning A records and not SRV records, there are no ports
listed, so this is only useful when you're querying for services running on
ports known to you in advance.

#### CNAME Records
If for an A or AAAA query the IP address can not be parsed, SkyDNS will try to see if there is
a chain of names that will lead to an IP address. The chain can not be longer than 8. So for instance
if the following services have been registered:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/production/rails/1 \
        -d value='{"host":"service1.skydns.local","port":8080}'

and

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/service1 \
        -d value='{"host":"10.0.2.15","port":8080}'

We have created the following CNAME chain: `1.rails.production.east.skydns.local` -> `service1.skydns.local` ->
`10.0.2.15`. If you then query for an A or AAAA for 1.rails.production.east.skydns.local SkyDNS returns:

    1.rails.production.east.skydns.local. 3600  IN  CNAME   server1.skydns.local.
    server1.skydns.local.                 3600  IN  A       10.0.2.15

#### NS Records

SkyDNS will internally synthesis name which will be used for NS records. The first
nameserver used will be named `ns1.dns.skydns.local` in the default setup . Extra
nameserver will be numbered ns2, ns3, etc. The subdomain `dns.skydns.local` will take
precedence over services with a similar name.

#### PTR Records: Reverse Addresses

When registering a service with an IP address only, you might also want to register
the reverse (the hostname the address points to). In the DNS these records are called
PTR records.

So looking back at some of the services in the section [](#service-discovery-via-the-dns),
we register these IP only ones:

    4.rails.staging.east.skydns.local. 10.0.1.125
    6.rails.stating.east.skydns.local. 2003::8:1

To add the reverse of these address you need to add the following names and values:

    125.1.0.10.in-addr.arpa. service1.example.com.
    1.0.0.0.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.2.ip6.arpa. service1.example.com.

These can be added with:

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/arpa/in-addr/10/0/1/125 \
        -d value='{"host":"service1.example.com}'
    TODO(miek): ipv6 value here

(Yes, the reverse of ip6 is not optimal.) If SkyDNS receives a PTR query it will check these paths and
will return the contents. Note that these replies are sent with the AA (Authoritative Answer) bit *off*.
If nothing is found locally the query is forwarded to the local recursor (if so configured), 
otherwise SERVFAIL is returned.

#### DNS Forwarding

By specifying nameservers in SkyDNS's config, for instance `8.8.8.8:53,8.8.4.4:53`,
you create a DNS forwarding proxy. In this case it round-robins between the two
nameserver IPs mentioned.

Requests for which SkyDNS isn't authoritative will be forwarded and proxied back to 
the client. This means that you can set SkyDNS as the primary DNS server in 
`/etc/resolv.conf` and use it for both service discovery and normal DNS operations.

#### DNSSEC

SkyDNS supports signing DNS answers, also known as DNSSEC. To use it, you need to
create a DNSSEC keypair and use that in SkyDNS. For instance, if the domain for
SkyDNS is `skydns.local`:

    % dnssec-keygen skydns.local
    Generating key pair............++++++ ...................................++++++
    Kskydns.local.+005+49860

This creates two files with the basename `Kskydns.local.+005.49860`, one with the
extension `.key` (this holds the public key) and one with the extension `.private` which
holds the private key. The basename of these files should be given to SkyDNS's DNSSEC configuration
option like so (together with some other options):

    curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config -d \
        value='{"dns_addr":"127.0.0.1:5354","dnssec":"Kskydns.local.+005+55656"}'

If you then query with `dig +dnssec` you will get signatures, keys and NSEC3 records returned.
Authenticated denial of existence is implemented using NSEC3 white lies, 
see [RFC7129](http://tools.ietf.org/html/rfc7129), Appendix B.

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
