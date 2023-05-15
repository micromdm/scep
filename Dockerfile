FROM golang:1.20-buster AS builder

WORKDIR /app
COPY ./ ./
RUN go build -v -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o bin/scepclient ./cmd/scepclient
RUN go build -v -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o bin/scepserver ./cmd/scepserver

FROM debian:buster-slim
COPY --from=builder /app/bin/scepclient /usr/bin/scepclient
COPY --from=builder /app/bin/scepserver /usr/bin/scepserver

EXPOSE 8080
VOLUME ["/depot"]
ENTRYPOINT ["scepserver"]
