package scepserver

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
)

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

func (r SCEPRequest) scepOperation() string { return r.Operation }

// SCEPResponse is a SCEP server response.
// Business errors will be encoded as a CertRep message
// with pkiStatus FAILURE and a failInfo attribute.
type SCEPResponse struct {
	operation string
	CACertNum int
	Data      []byte
	Err       error
}

func (r SCEPResponse) scepOperation() string { return r.operation }

// EndpointLoggingMiddleware returns an endpoint middleware that logs the
// duration of each invocation, and the resulting error, if any.
func EndpointLoggingMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			var keyvals []interface{}
			// check if this is a scep endpoint, if it is, append the method to the log.
			if oper, ok := request.(interface {
				scepOperation() string
			}); ok {
				keyvals = append(keyvals, "method", oper.scepOperation())
			}
			defer func(begin time.Time) {
				logger.Log(append(keyvals, "error", err, "took", time.Since(begin))...)
			}(time.Now())
			return next(ctx, request)

		}
	}
}
