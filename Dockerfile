FROM crosbymichael/golang
MAINTAINER Miek Gieben <miek@miek.nl> (@miekg)

RUN apt-get update && apt-get install --no-install-recommends -y \
    dnsutils

ADD . /go/src/github.com/skynetservices/skydns
RUN go get github.com/skynetservices/skydns

EXPOSE 53
ENTRYPOINT ["skydns"]
