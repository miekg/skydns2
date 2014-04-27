curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/config -d value='{"dns_addr":"127.0.0.1:5354"}'
curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/b1 -d value='{"Port":80,"Priority":10,"Host": "10.0.1.3"'}
curl -XPUT http://127.0.0.1:4001/v2/keys/skydns/local/skydns/east/a1 -d value='{"Port":80,"Priority":10,"Host": "web.google.nl"'}
