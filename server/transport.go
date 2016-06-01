package scepserver

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	kitlog "github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/micromdm/scep/scep"
	"golang.org/x/net/context"
)

// ServiceHandler is an HTTP Handler for a SCEP endpoint.
func ServiceHandler(ctx context.Context, svc Service, logger kitlog.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorLogger(logger),
	}

	scepHandler := kithttp.NewServer(
		ctx,
		makeSCEPEndpoint(svc),
		decodeSCEPRequest,
		encodeSCEPResponse,
		opts...,
	)

	mux := http.NewServeMux()
	mux.Handle("/scep", scepHandler)
	return mux
}

// DecodeSCEPRequest decodes an HTTP request to the SCEP server
// extracting the Operation and Message.
func decodeSCEPRequest(_ context.Context, r *http.Request) (interface{}, error) {
	q := r.URL.Query()
	var requestErr error // an error that should be encoded in the response
	if _, ok := q["operation"]; !ok {
		requestErr = errors.New("bad request")
		return SCEPRequest{Err: requestErr}, nil
	}

	msg, err := message(r)
	if err != nil {
		return nil, err
	}

	var pkiMessage *scep.PKIMessage
	if len(msg) > 0 {
		p, err := scep.ParsePKIMessage(msg)
		if err != nil { // should this be a requestErr?
			return nil, err
		}
		pkiMessage = p
	}

	request := SCEPRequest{
		Operation:  q.Get("operation"),
		Message:    msg,
		PKIMessage: pkiMessage,
	}

	return request, nil
}

// extract message from request
func message(r *http.Request) ([]byte, error) {
	switch r.Method {
	case "GET":
		var msg string
		q := r.URL.Query()
		if _, ok := q["message"]; ok {
			msg = q.Get("message")
		}
		return []byte(msg), nil
	case "POST":
		return ioutil.ReadAll(r.Body)
	default:
		return nil, errors.New("method not supported")
	}
}

// EncodeSCEPResponse writes a SCEP response back to the SCEP client.
func encodeSCEPResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(SCEPResponse)
	if resp.Err != nil {
		fmt.Println(resp.Err)
	}
	if len(resp.Data) > 0 { //use data field
		w.Write(resp.Data)
		return nil
	}
	if resp.PKIMessage != nil {
		w.Write(resp.PKIMessage.Raw)
		return nil
	}
	return nil
}

func makeSCEPEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(SCEPRequest)

		switch req.Operation {
		case "GetCACaps":
			caps, err := svc.GetCACaps(ctx)
			if err != nil {
				return SCEPResponse{Err: err}, nil
			}
			return SCEPResponse{Data: caps}, nil
		default:
			return nil, errors.New("not implemented")
		}
	}
}
