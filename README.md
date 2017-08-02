`scep` is a Simple Certificate Enrollment Protocol server and client

# Installation
A binary release is available on the releases page.

## Compiling
To compile the SCEP client and server, there are a few requirements.
* You must have a Go compiler. The compiler is normally in the `golang` package.
* You must have a shell variable set for $GOPATH. This is a directory used by the Go compiler and utilities for all Go projects.

1. Once all of those are set, clone the repository with `go get github.com/micromdm/scep`
2. Install dependencies:
    `make deps`
3. Compile the server and client binaries: 
    `make build`
The binaries will be compiled in the `build/` folder.


# Example
minimal example for both server and client
```
# create a new CA
scepserver ca -init
# start server
scepserver -depot depot -port 2016 -challenge=secret

# SCEP request:
# in a separate terminal window, run a client
# note, if the client.key doesn't exist, the client will create a new rsa private key. Must be in PEM format.
scepclient -private-key client.key -server-url=http://scep.groob.io:2016/scep -challenge=secret

# NDES request:
scepclient -private-key client.key -server-url=http://scep.groob.io:2016/certsrv/mscep/ -ca-fingerprint="81C827D2 3DAAF3B4 73999632 67609B30"
```
# Server Usage

The default flags configure and run the scep server.  
depot must be the path to a folder with `ca.pem` and `ca.key` files. 

If you don't already have a CA to use, you can create one using the `scep ca` subcommand.

The server currently has two endpoints:
- /scep
- /certsrv/mscep

To obtain a signed SCEP certificate, you will use the /scep endpoint.

To obtain a certificate through Network Device Enrollment Service (NDES), use the /certsrv/mscep endpoint. You will need to add the `ca-fingerprint` client argument during this request.

```
Usage of ./cmd/scepserver/scepserver:
  -challenge string
    	enforce a challenge password
  -depot string
    	path to ca folder (default "depot")
  -port string
    	port to listen on (default "8080")
  -version
    	prints version information
```

`scep ca -init` to create a new CA and private key. 

```
Usage of ./cmd/scepserver/scepserver ca:
  -country string
    	country for CA cert (default "US")
  -depot string
    	path to ca folder (default "depot")
  -init
    	create a new CA
  -key-password string
    	password to store rsa key
  -keySize int
    	rsa key size (default 4096)
  -organization string
    	organization for CA cert (default "scep-ca")
  -years int
    	default CA years (default 10)
```

# Client Usage


```
Usage of scepclient:
  -certificate string
    	certificate path, if there is no key, scepclient will create one
  -challenge string
    	enforce a challenge password
  -cn string
    	common name for certificate (default "scepclient")
  -country string
    	country code in certificate (default "US")
  -keySize int
    	rsa key size (default 2048)
  -organization string
    	organization for cert (default "scep-client")
  -private-key string
    	private key path, if there is no key, scepclient will create one
  -server-url string
    	SCEP server url
  -version
    	prints version information
```

Note: Make sure to specify the desired endpoint in your `-server-url` value (e.g. `'http://scep.groob.io:2016/scep'`)

# Docker
```
docker pull micromdm/scep
# create CA
docker run -it --rm -v /path/to/ca/folder:/depot micromdm/scep ./scep ca -init

# run
docker run -it --rm -v /path/to/ca/folder:/depot -p 8080:8080 micromdm/scep
```

# SCEP library

```
go get github.com/micromdm/scep/scep
```

For detailed usage, see [godoc](https://godoc.org/github.com/micromdm/scep/scep) 

Example:
```
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

// use the csr from decrypted PKCRS request
csr := msg.CSRReqMessage.CSR

// create cert template
tmpl := &x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject:      csr.Subject,
	NotBefore:    time.Now().Add(-600).UTC(),
	NotAfter:     time.Now().AddDate(1, 0, 0).UTC(),
	SubjectKeyId: id,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageClientAuth,
	},
}

// create a CertRep message from the original
certRep, err := msg.SignCSR(CAcert, CAkey, tmlp)
if err != nil {
    // handle err
}

// send response back
// w is a http.ResponseWriter
w.Write(certRep.Raw)
```

# Server library

You can import the scep endpoint into another Go project. For an example take a look at `cmd/scep/main.go`
