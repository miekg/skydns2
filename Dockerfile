FROM progrium/busybox
MAINTAINER Miek Gieben <miek@miek.nl> (@miekg)

RUN opkg-install bind-dig

ADD skydns skydns

EXPOSE 53 53/udp
ENTRYPOINT ["/skydns"]
