package scepserver

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	kitlog "github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"
	"golang.org/x/net/context"
)

// ServiceHandler is an HTTP Handler for a SCEP endpoint.
func ServiceHandler(ctx context.Context, svc Service, logger kitlog.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorLogger(logger),
		kithttp.ServerBefore(updateContext),
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

func updateContext(ctx context.Context, r *http.Request) context.Context {
	q := r.URL.Query()
	if _, ok := q["operation"]; ok {
		ctx = context.WithValue(ctx, "operation", q.Get("operation"))
	}
	return ctx
}

// DecodeSCEPRequest decodes an HTTP request to the SCEP server
// extracting the Operation and Message.
func decodeSCEPRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	msg, err := message(r)
	if err != nil {
		return nil, err
	}

	request := SCEPRequest{
		Message: msg,
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
func encodeSCEPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(SCEPResponse)
	if resp.Err != nil {
		fmt.Println(resp.Err)
		return resp.Err
	}
	w.Header().Set("Content-Type", contentHeader(ctx))
	w.Write(resp.Data)
	return nil
}

const (
	certChainHeader = "application/x-x509-ca-ra-cert"
	pkiOpHeader     = "application/x-pki-message"
)

func contentHeader(ctx context.Context) string {
	op := ctx.Value("operation")
	switch op {
	case "GetCACert":
		return certChainHeader
	case "PKIOperation":
		return pkiOpHeader
	default:
		return "text/plain"
	}
}

func makeSCEPEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		op := ctx.Value("operation")
		if op == nil {
			return SCEPResponse{Err: errors.New("unknown operation")}, nil
		}
		req := request.(SCEPRequest)
		switch op {
		case "GetCACaps":
			caps, err := svc.GetCACaps(ctx)
			if err != nil {
				return SCEPResponse{Err: err}, nil
			}
			return SCEPResponse{Data: caps}, nil
		case "GetCACert":
			cert, err := svc.GetCACert(ctx)
			if err != nil {
				return SCEPResponse{Err: err}, nil
			}
			return SCEPResponse{Data: cert}, nil
		case "PKIOperation":
			resp, err := svc.PKIOperation(ctx, req.Message)
			if err != nil {
				return SCEPResponse{Err: err}, nil
			}
			return SCEPResponse{Data: resp}, nil
		default:
			return nil, errors.New("not implemented")
		}
	}
}
