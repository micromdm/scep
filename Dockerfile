FROM alpine:3.6

COPY ./build/scepserver-linux-amd64 /usr/bin/scepserver
COPY ./build/scepclient-linux-amd64 /usr/bin/scepclient

EXPOSE 8080

ENTRYPOINT ["scepserver"]
