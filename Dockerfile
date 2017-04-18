FROM alpine:3.5

ENV SCEP_VERSION=v1.0.0
RUN apk --no-cache add curl unzip && \
    curl -L https://github.com/micromdm/scep/releases/download/${SCEP_VERSION}/scep.zip -o /scep.zip && \
    unzip -p /scep.zip build/scepserver-linux-amd64 > /scep && \
    rm /scep.zip && \
    chmod a+x /scep && \
    apk del curl unzip

CMD ["/scep"]
