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

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

func main() {
	// flags
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flPort              = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "port to listen on")
		flDepotPath         = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flChallengePassword = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
	)
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scep - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}
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
		svcOptions := []scepserver.ServiceOption{
			scepserver.ChallengePassword(*flChallengePassword),
		}
		svc, err = scepserver.NewService(depot, svcOptions...)
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
		svc = scepserver.NewLoggingService(log.NewContext(logger).With("component", "service"), svc)
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
