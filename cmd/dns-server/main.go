package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dns-server/internal/config"
	"dns-server/internal/server"
	"dns-server/pkg/logger"

	"github.com/sirupsen/logrus"
)

var (
	configPath = flag.String("config", "config.toml", "path to configuration file")
	version    = flag.Bool("version", false, "show version information")
)

const (
	appName    = "dns-server"
	appVersion = "1.0.0"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s version %s\n", appName, appVersion)
		os.Exit(0)
	}

	configLoader := config.NewTOMLConfigLoader()
	cfg, err := configLoader.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	log := logger.NewLogger(&cfg.Logging)

	log.WithFields(logrus.Fields{
		"version":     appVersion,
		"config_file": *configPath,
	}).Info("starting DNS server")

	srv, err := server.NewServer(cfg, log)
	if err != nil {
		log.WithError(err).Fatal("failed to create server")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.WithField("signal", sig.String()).Info("received shutdown signal")
		cancel()
	}()

	if err := srv.Start(ctx); err != nil {
		log.WithError(err).Fatal("failed to start server")
	}

	srv.Wait()
	log.Info("DNS server shutdown complete")
}
