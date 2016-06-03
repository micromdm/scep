package scep

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/micromdm/scep/server"
)

// SCEP holds the configuration for the SCEP server
type SCEP struct {
	next              middleware.Handler
	challengePassword string
	depotPath         string // cert store path
	caKeyPassword     []byte
	scepHandler       http.Handler
}

func (s SCEP) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	paths := []string{"/scep"}
	for _, p := range paths {
		if middleware.Path(r.URL.Path).Matches(p) {
			s.scepHandler.ServeHTTP(w, r)
			return 0, nil
		}
	}
	return s.next.ServeHTTP(w, r)
}

// Setup creates a caddy middleware
func Setup(c *setup.Controller) (middleware.Middleware, error) {
	scp, err := parse(c)
	if err != nil {
		return nil, err
	}

	// Runs on Caddy startup, useful for services or other setups.
	c.Startup = append(c.Startup, func() error {
		fmt.Println("scep middleware is initiated")
		return nil
	})

	// Runs on Caddy shutdown, useful for cleanups.
	c.Shutdown = append(c.Shutdown, func() error {
		fmt.Println("api middleware is cleaning up")
		return nil
	})
	ctx := context.Background()

	// go kig logger
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.NewContext(logger).With("ts", log.DefaultTimestampUTC)
		logger = log.NewContext(logger).With("caller", log.DefaultCaller)
	}
	// scep cert depot
	var depot scepserver.Depot // cert storage
	{
		depot, err = scepserver.NewFileDepot(scp.depotPath)
		if err != nil {
			return nil, err
		}
	}
	// scep service
	var svc scepserver.Service // scep service
	{
		svcOptions := []scepserver.ServiceOption{
			scepserver.ChallengePassword(scp.challengePassword),
		}
		svc, err = scepserver.NewService(depot, svcOptions...)
		if err != nil {
			return nil, err
		}
		svc = scepserver.NewLoggingService(log.NewContext(logger).With("component", "service"), svc)
	}

	// scep handler
	var h http.Handler
	{
		h = scepserver.ServiceHandler(ctx, svc, log.NewContext(logger).With("component", "http"))
	}

	// caddy middleware
	var m middleware.Middleware
	{
		m = func(next middleware.Handler) middleware.Handler {
			scp.next = next
			scp.scepHandler = h
			return scp
		}
	}

	return m, nil
}

func parse(c *setup.Controller) (*SCEP, error) {
	var (
		config *SCEP
		err    error
	)

	for c.Next() {
		config = &SCEP{}
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
		case 1:
		default:
			return nil, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "depot":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.depotPath = filepath.Clean(c.Root + string(filepath.Separator) + c.Val())
			case "keypass":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.caKeyPassword = []byte(c.Val())
			case "challenge":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.challengePassword = c.Val()
			default:
				return nil, c.ArgErr()
			}
		}
	}
	return config, err
}
