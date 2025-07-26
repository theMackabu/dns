package upstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type DNSResolver interface {
	Resolve(ctx context.Context, question dns.Question) (*dns.Msg, error)
}

type UpstreamResolver struct {
	servers []string
	timeout time.Duration
	retries int
	client  *dns.Client
	logger  *logrus.Logger
	pool    sync.Pool
}

func NewUpstreamResolver(servers []string, timeout time.Duration, retries int, logger *logrus.Logger) *UpstreamResolver {
	resolver := &UpstreamResolver{
		servers: servers,
		timeout: timeout,
		retries: retries,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		logger: logger,
	}

	resolver.pool = sync.Pool{
		New: func() any {
			return &dns.Msg{}
		},
	}

	return resolver
}

func (r *UpstreamResolver) Resolve(ctx context.Context, question dns.Question) (*dns.Msg, error) {
	msg := r.pool.Get().(*dns.Msg)
	defer r.pool.Put(msg)

	msg.Id = dns.Id()
	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = true

	var lastErr error

	for attempt := 0; attempt <= r.retries; attempt++ {
		for _, server := range r.servers {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			response, err := r.queryServer(ctx, msg, server)
			if err != nil {
				lastErr = err
				r.logger.WithFields(logrus.Fields{
					"server":  server,
					"attempt": attempt + 1,
					"error":   err,
				}).Debug("upstream query failed")
				continue
			}

			if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
				r.logger.WithFields(logrus.Fields{
					"server":   server,
					"question": question.Name,
					"qtype":    dns.TypeToString[question.Qtype],
					"rcode":    dns.RcodeToString[response.Rcode],
				}).Debug("upstream query successful")
				return response, nil
			}

			lastErr = fmt.Errorf("server returned error code: %s", dns.RcodeToString[response.Rcode])
		}

		if attempt < r.retries {
			backoff := time.Duration(attempt+1) * 100 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("all upstream servers failed")
	}

	return nil, fmt.Errorf("failed to resolve %s after %d attempts: %w", question.Name, r.retries+1, lastErr)
}

func (r *UpstreamResolver) queryServer(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	response, _, err := r.client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, fmt.Errorf("exchange failed with %s: %w", server, err)
	}

	return response, nil
}

func (r *UpstreamResolver) SetServers(servers []string) {
	if len(servers) == 0 {
		return
	}
	r.servers = make([]string, len(servers))
	copy(r.servers, servers)
}

func (r *UpstreamResolver) GetServers() []string {
	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	return servers
}

func (r *UpstreamResolver) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
	r.client.Timeout = timeout
}

func (r *UpstreamResolver) SetRetries(retries int) {
	if retries >= 0 {
		r.retries = retries
	}
}
