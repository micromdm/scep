SCEP server and Go library

# Standalone server and client binaries
A standalone go server is available under `cmd/scep/main.go`

```
Usage of ./cmd/scep/scep:
  -depot string
    	path to ca folder (default "depot")
  -port string
    	port to listen on (default "8080")
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
