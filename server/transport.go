package scepserver

import (
	"errors"
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
	return nil, nil
}

// EncodeSCEPResponse writes a SCEP response back to the SCEP client.
func encodeSCEPResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	return nil
}

func makeSCEPEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		return nil, errors.New("not implemented")
	}
}
