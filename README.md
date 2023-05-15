# scep

[![CI](https://github.com/pidpawel/scep/workflows/CI/badge.svg)](https://github.com/pidpawel/scep/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidpawel/scep/v2.svg)](https://pkg.go.dev/github.com/pidpawel/scep/v2)

`scep` is a Simple Certificate Enrollment Protocol server and client.

## Installation

### Using `go`

```bash
go install github.com/pidpawel/scep@latest
```

### Manual binary install

Binary releases are available on the [releases page](https://github.com/pidpawel/scep/releases).

### Compilation from source

To compile the SCEP client and server you will need [a Go compiler](https://golang.org/dl/) as well as standard tools like git, etc.

```bash
git clone https://github.com/pidpawel/scep.git
cd scep
go build -o scepclient ./cmd/scepclient/
go build -o scepserver ./cmd/scepserver/
```

### Building Docker

```bash
git clone https://github.com/pidpawel/scep.git
cd scep
docker build -t micromdm/scep:latest .
```

## Usage principles

### Server

The scepserver provides one HTTP endpoint, `/scep`, that facilitates the normal PKIOperation/Message parameters.

In order to do so it needs a CA key and certificate. They're stored in a directory called `depot`. `-depot` must be the path to a folder with `ca.pem` and `ca.key` files.

If you don't already have a CA to use, you can create one using the `ca` subcommand: `./scepserver ca -init`, or with Docker `docker run --rm -it -v ./secp-depot:/depot micromdm/scep:latest ca -init`.

In order to start the server **manually**:

```bash
./scepserver -depot secp-depot -challenge=secret
```

If you want to use **Docker** instead:

```bash
docker run -it --rm -v ./secp-depot:/depot -p 8080:8080 micromdm/scep:latest
```

If you want to use **Docker compose**:

```docker-compose
version: "3.9"
services:
  scep:
    image: micromdm/scep:latest
    ports:
      - "8080:8080"
    volumes:
      - ./secp-depot:/depot
```

### CSR verifier server addon

The `-csrverifierexec` switch to the `scepserver` allows for executing a command before a certificate is issued to verify the submitted CSR. Scripts exiting without errors (zero exit status) will proceed to certificate issuance, otherwise a SCEP error is generated to the client. For example if you wanted to just save the CSR this is a valid CSR verifier shell script:

```sh
#!/bin/sh

cat - >> /tmp/scep.csr
```

### Client

Note: you only need one of this.

```bash
# SCEP request:
# Note: if the client.key doesn't exist, the client will create a new rsa private key.
# Note: client.key must be in PEM format.
./scepclient -private-key client.key -server-url=http://127.0.0.1:8080/scep -challenge=secret

# NDES request:
# Note: this should point to an NDES server, scepserver does not provide NDES.
./scepclient -private-key client.key -server-url=https://scep.example.com:4321/certsrv/mscep/ -ca-fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

Note: Make sure to specify the desired endpoint in your `-server-url` value (e.g. `'http://scep.groob.io:8080/scep'`)

To obtain a certificate through Network Device Enrollment Service (NDES), set `-server-url` to a server that provides NDES.
This most likely uses the `/certsrv/mscep` path. You will need to add the `-ca-fingerprint` client argument during this request to specify which CA to use.

If you're not sure which SHA-256 hash (for a specific CA) to use, you can use the `-debug` flag to print them out for the CAs returned from the SCEP server.

### SCEP library

The core `scep` library can be used for both client and server operations.

```bash
go get github.com/pidpawel/scep/scep
```

For detailed usage, see the [Go Reference](https://pkg.go.dev/github.com/pidpawel/scep/v2/scep).

#### Example server

```go
// read a request body containing SCEP message
body, err := ioutil.ReadAll(r.Body)
if err != nil {
    // handle err
}

// parse the SCEP message
msg, err := scep.ParsePKIMessage(body)
if err != nil {
    // handle err
}

// do something with msg
fmt.Println(msg.MessageType)

// extract encrypted pkiEnvelope
err := msg.DecryptPKIEnvelope(CAcert, CAkey)
if err != nil {
    // handle err
}

// use the CSR from decrypted PKCS request and sign
// MyCSRSigner returns an *x509.Certificate here
crt, err := MyCSRSigner(msg.CSRReqMessage.CSR)
if err != nil {
    // handle err
}

// create a CertRep message from the original
certRep, err := msg.Success(CAcert, CAkey, crt)
if err != nil {
    // handle err
}

// send response back
// w is a http.ResponseWriter
w.Write(certRep.Raw)
```

#### Server library

You can import the scep endpoint into another Go project. For an example take a look at [scepserver.go](cmd/scepserver/scepserver.go).

The SCEP server includes a built-in CA/certificate store. This is facilitated by the `Depot` and `CSRSigner` Go interfaces. This certificate storage to happen however you want. It also allows for swapping out the entire CA signer altogether or even using SCEP as a proxy for certificates.
