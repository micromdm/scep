`scep` is a Simple Certificate Enrollment Protocol server.

# Installation
A binary release is available on the releases page.

# Usage

The default flags configure and run the scep server.  
depot must be the path to a folder with `ca.pem` and `ca.key` files. 

If you don't already have a CA to use, you can create one using the `scep ca` subcommand.

```
Usage of ./cmd/scep/scep:
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
Usage of ./cmd/scep/scep ca:
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
