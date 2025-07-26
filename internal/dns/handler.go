package dns

import (
	"context"
	"strings"
	"time"

	"dns-server/internal/cache"
	"dns-server/internal/resolver"
	"dns-server/internal/upstream"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	cache         cache.Cache
	localResolver *resolver.LocalResolver
	resolver      upstream.DNSResolver
	logger        *logrus.Logger
}

func NewHandler(cache cache.Cache, localResolver *resolver.LocalResolver, resolver upstream.DNSResolver, logger *logrus.Logger) *Handler {
	return &Handler{
		cache:         cache,
		localResolver: localResolver,
		resolver:      resolver,
		logger:        logger,
	}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response := &dns.Msg{}
	response.SetReply(r)
	response.Authoritative = false
	response.RecursionAvailable = true

	if len(r.Question) == 0 {
		response.Rcode = dns.RcodeFormatError
		h.writeResponse(w, response)
		return
	}

	question := r.Question[0]

	if !h.isSupportedType(question.Qtype) {
		h.logger.WithFields(logrus.Fields{
			"question": question.Name,
			"qtype":    dns.TypeToString[question.Qtype],
		}).Debug("unsupported query type")

		response.Rcode = dns.RcodeNotImplemented
		h.writeResponse(w, response)
		return
	}

	cacheKey := cache.GenerateCacheKey(question)

	if cachedResponse, found := h.cache.Get(cacheKey); found {
		h.logger.WithFields(logrus.Fields{
			"question": question.Name,
			"qtype":    dns.TypeToString[question.Qtype],
		}).Debug("cache hit")

		cachedResponse.Id = r.Id
		h.writeResponse(w, cachedResponse)
		return
	}

	if localResponse, found := h.localResolver.Resolve(question); found {
		h.logger.WithFields(logrus.Fields{
			"question": question.Name,
			"qtype":    dns.TypeToString[question.Qtype],
		}).Debug("local record resolved")

		localResponse.Id = r.Id

		ttl := h.extractTTL(localResponse)
		if ttl > 0 {
			h.cache.Set(cacheKey, localResponse, ttl)
		}

		h.writeResponse(w, localResponse)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"question": question.Name,
		"qtype":    dns.TypeToString[question.Qtype],
	}).Debug("cache miss and no local record, forwarding to upstream")

	upstreamResponse, err := h.resolver.Resolve(ctx, question)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"question": question.Name,
			"qtype":    dns.TypeToString[question.Qtype],
			"error":    err,
		}).Error("upstream resolution failed")

		response.Rcode = dns.RcodeServerFailure
		h.writeResponse(w, response)
		return
	}

	upstreamResponse.Id = r.Id

	ttl := h.extractTTL(upstreamResponse)
	if ttl > 0 {
		h.cache.Set(cacheKey, upstreamResponse, ttl)
	}

	h.writeResponse(w, upstreamResponse)
}

func (h *Handler) isSupportedType(qtype uint16) bool {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSOA, dns.TypePTR, dns.TypeHTTPS, dns.TypeCAA, dns.TypeSRV, dns.TypeSVCB, dns.TypeDS, dns.TypeDNSKEY, dns.TypeURI, dns.TypeNAPTR, dns.TypeSSHFP, dns.TypeTLSA, dns.TypeSMIMEA, dns.TypeCERT:
		return true
	default:
		return false
	}
}

func (h *Handler) extractTTL(msg *dns.Msg) time.Duration {
	if len(msg.Answer) == 0 {
		return 300 * time.Second
	}

	minTTL := uint32(3600)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	if minTTL < 60 {
		minTTL = 60
	}

	return time.Duration(minTTL) * time.Second
}

func (h *Handler) writeResponse(w dns.ResponseWriter, msg *dns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		h.logger.WithError(err).Error("failed to write DNS response")
	}
}

func (h *Handler) logQuery(r *dns.Msg, clientAddr string) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	h.logger.WithFields(logrus.Fields{
		"client":   clientAddr,
		"question": strings.TrimSuffix(question.Name, "."),
		"qtype":    dns.TypeToString[question.Qtype],
		"qclass":   dns.ClassToString[question.Qclass],
	}).Info("DNS query received")
}

func (h *Handler) HandleQuery(w dns.ResponseWriter, r *dns.Msg) {
	clientAddr := w.RemoteAddr().String()
	h.logQuery(r, clientAddr)
	h.ServeDNS(w, r)
}
