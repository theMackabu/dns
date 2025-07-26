package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"dns-server/internal/cache"
	"dns-server/internal/config"
	dnshandler "dns-server/internal/dns"
	"dns-server/internal/resolver"
	"dns-server/internal/upstream"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Server struct {
	config        *config.Config
	cache         cache.Cache
	localResolver *resolver.LocalResolver
	resolver      upstream.DNSResolver
	handler       *dnshandler.Handler
	server        *dns.Server
	logger        *logrus.Logger
	wg            sync.WaitGroup
}

func NewServer(cfg *config.Config, logger *logrus.Logger) (*Server, error) {
	dnsCache := cache.NewLRUCache(
		cfg.Cache.MaxEntries,
		cfg.Cache.DefaultTTL,
		cfg.Cache.CleanupInterval,
	)

	if err := dnsCache.LoadFromFile("dns-cache.gob"); err != nil {
		logger.WithError(err).Debug("no cache file found or failed to load cache")
	} else {
		logger.WithField("size", dnsCache.Size()).Info("cache loaded from dns-cache.gob")
	}

	upstreamResolver := upstream.NewUpstreamResolver(
		cfg.Upstream.Servers,
		cfg.Upstream.Timeout,
		cfg.Upstream.Retries,
		logger,
	)

	localResolver := resolver.NewLocalResolver(&cfg.Records, logger)

	handler := dnshandler.NewHandler(dnsCache, localResolver, upstreamResolver, logger)

	addr := fmt.Sprintf("%s:%d", cfg.Server.BindAddress, cfg.Server.Port)

	server := &dns.Server{
		Addr:         addr,
		Net:          "udp",
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		UDPSize:      65535,
	}

	return &Server{
		config:        cfg,
		cache:         dnsCache,
		localResolver: localResolver,
		resolver:      upstreamResolver,
		handler:       handler,
		server:        server,
		logger:        logger,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.WithFields(logrus.Fields{
		"address": s.server.Addr,
		"network": s.server.Net,
	}).Info("starting DNS server")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.ListenAndServe(); err != nil {
			s.logger.WithError(err).Error("DNS server stopped")
		}
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.logger.Info("shutting down DNS server")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.server.ShutdownContext(shutdownCtx); err != nil {
			s.logger.WithError(err).Error("error during server shutdown")
		}
	}()

	if err := s.waitForServer(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	s.logger.Info("DNS server started successfully")
	return nil
}

func (s *Server) Stop() {
	s.logger.Info("stopping DNS server")

	if s.cache != nil {
		if lruCache, ok := s.cache.(*cache.LRUCache); ok {
			lruCache.Close()
		}

		if err := s.cache.DumpToFile("dns-cache.gob"); err != nil {
			s.logger.WithError(err).Warn("failed to dump cache to disk")
		} else {
			s.logger.Info("cache dumped to dns-cache.gob")
		}
	}

	s.logger.Info("DNS server stopped")
}

func (s *Server) Wait() {
	s.wg.Wait()
	s.Stop()
}

func (s *Server) waitForServer() error {
	maxAttempts := 10
	for i := range maxAttempts {
		conn, err := net.DialTimeout("udp", s.server.Addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}

		if i == maxAttempts-1 {
			return fmt.Errorf("server failed to start after %d attempts: %w", maxAttempts, err)
		}

		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (s *Server) GetStats() map[string]any {
	stats := map[string]any{
		"cache_size":     s.cache.Size(),
		"server_address": s.server.Addr,
	}

	if upstreamResolver, ok := s.resolver.(*upstream.UpstreamResolver); ok {
		stats["upstream_servers"] = upstreamResolver.GetServers()
	}

	return stats
}
