FROM alpine:3.6

COPY ./scepclient-linux-amd64 /usr/bin/scepclient
COPY ./scepserver-linux-amd64 /usr/bin/scepserver

EXPOSE 8080

RUN ["/usr/bin/scepserver", "ca", "-init"]

CMD ["/usr/bin/scepserver"]
