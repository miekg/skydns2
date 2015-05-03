FROM accursoft/micro-jessie
MAINTAINER Miek Gieben <miek@miek.nl> (@miekg)

RUN apt-get update && apt-get install --no-install-recommends -y dnsutils

ADD skydns skydns

EXPOSE 53 53/udp
ENTRYPOINT ["/skydns"]
