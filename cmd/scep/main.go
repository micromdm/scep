package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/micromdm/scep/server"
	"golang.org/x/net/context"
)

func main() {
	// flags
	var (
		flPort      = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "port to listen on")
		flDepotPath = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
	)
	flag.Parse()
	port := ":" + *flPort
	ctx := context.Background()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.NewContext(logger).With("ts", log.DefaultTimestampUTC)
		logger = log.NewContext(logger).With("caller", log.DefaultCaller)
	}

	var err error
	var depot scepserver.Depot // cert storage
	{
		depot, err = scepserver.NewFileDepot(*flDepotPath)
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
	}

	var svc scepserver.Service // scep service
	{
		svc, err = scepserver.NewService(depot, []byte(""))
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
	}

	var h http.Handler // http handler
	{
		h = scepserver.ServiceHandler(ctx, svc, log.NewContext(logger).With("component", "http"))
	}

	// start http server
	errs := make(chan error, 2)
	go func() {
		logger.Log("transport", "http", "address", port, "msg", "listening")
		errs <- http.ListenAndServe(port, h)
	}()
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	logger.Log("terminated", <-errs)
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}
