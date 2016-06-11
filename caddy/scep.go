package scep

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/micromdm/scep/server"
)

// SCEP holds the configuration for the SCEP server
type SCEP struct {
	next              httpserver.Handler
	challengePassword string
	depotPath         string // cert store path
	caKeyPassword     []byte
	scepHandler       http.Handler
}

func (s SCEP) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	paths := []string{"/scep"}
	for _, p := range paths {
		if httpserver.Path(r.URL.Path).Matches(p) {
			s.scepHandler.ServeHTTP(w, r)
			return 0, nil
		}
	}
	return s.next.ServeHTTP(w, r)
}

func init() {
	caddy.RegisterPlugin("scep", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// Setup creates a caddy middleware
func setup(c *caddy.Controller) error {
	scp, err := parse(c)
	if err != nil {
		return err
	}

	// Runs on Caddy startup, useful for services or other setups.
	c.OnStartup(func() error {
		fmt.Println("scep middleware is initiated")
		return nil
	})

	// Runs on Caddy shutdown, useful for cleanups.
	c.OnShutdown(func() error {
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
			return err
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
			return err
		}
		svc = scepserver.NewLoggingService(log.NewContext(logger).With("component", "service"), svc)
	}

	// scep handler
	var h http.Handler
	{
		h = scepserver.ServiceHandler(ctx, svc, log.NewContext(logger).With("component", "http"))
	}

	// caddy middleware
	var m httpserver.Middleware
	{
		m = func(next httpserver.Handler) httpserver.Handler {
			scp.next = next
			scp.scepHandler = h
			return scp
		}
	}
	cfg := httpserver.GetConfig(c.Key)
	cfg.AddMiddleware(m)
	return nil
}

func parse(c *caddy.Controller) (*SCEP, error) {
	var (
		config *SCEP
		err    error
		cfg    = httpserver.GetConfig(c.Key)
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
				config.depotPath = filepath.Clean(cfg.Root + string(filepath.Separator) + c.Val())
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
