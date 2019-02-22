FROM golang:alpine

RUN apk add --no-cache git

RUN go get gopkg.in/yaml.v2
RUN go get github.com/gorilla/mux
RUN go get golang.org/x/time/rate
RUN go get github.com/golang/groupcache/lru
RUN go get github.com/miekg/dns

RUN apk del git


RUN mkdir /go/src/dnsrecon
ADD . /go/src/dnsrecon
WORKDIR /go/src/dnsrecon


RUN go build -o dnsrecon .


RUN adduser -S -D -H -h /go/src/dnsrecon user
USER user

CMD ["./dnsrecon"]
