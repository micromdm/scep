FROM golang:alpine3.16 as builder

WORKDIR /scep

COPY . /scep/

RUN apk add --update make && make


FROM alpine:3.16

COPY --from=builder /scep/scepclient-linux-amd64 /usr/bin/scepclient
COPY --from=builder /scep/scepserver-linux-amd64 /usr/bin/scepserver

EXPOSE 8080

VOLUME ["/depot"]

ENTRYPOINT ["scepserver"]
