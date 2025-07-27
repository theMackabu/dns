package resolver

import (
	"net"
	"strings"

	"dns-server/internal/config"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type LocalResolver struct {
	records *config.RecordsConfig
	logger  *logrus.Logger
}

func NewLocalResolver(records *config.RecordsConfig, logger *logrus.Logger) *LocalResolver {
	return &LocalResolver{
		records: records,
		logger:  logger,
	}
}

func (r *LocalResolver) Resolve(question dns.Question) (*dns.Msg, bool) {
	domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	response := &dns.Msg{}
	response.SetReply(&dns.Msg{Question: []dns.Question{question}})
	response.Authoritative = true
	response.RecursionAvailable = false

	var found bool
	var rr dns.RR

	switch question.Qtype {
	case dns.TypeA:
		if ip, exists := r.records.A[domain]; exists {
			if parsedIP := net.ParseIP(ip); parsedIP != nil && parsedIP.To4() != nil {
				rr = &dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: parsedIP.To4(),
				}
				found = true
			}
		}

	case dns.TypeAAAA:
		if ip, exists := r.records.AAAA[domain]; exists {
			if parsedIP := net.ParseIP(ip); parsedIP != nil && parsedIP.To16() != nil {
				rr = &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: parsedIP.To16(),
				}
				found = true
			}
		}

	case dns.TypeCNAME:
		if target, exists := r.records.CNAME[domain]; exists {
			if !strings.HasSuffix(target, ".") {
				target += "."
			}
			rr = &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: target,
			}
			found = true
		}

	case dns.TypeMX:
		if mx, exists := r.records.MX[domain]; exists {
			target := mx.Target
			if !strings.HasSuffix(target, ".") {
				target += "."
			}
			rr = &dns.MX{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Preference: uint16(mx.Priority),
				Mx:         target,
			}
			found = true
		}

	case dns.TypeTXT:
		if txt, exists := r.records.TXT[domain]; exists {
			rr = &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{txt},
			}
			found = true
		}

	case dns.TypeHTTPS:
		if httpsRecord, exists := r.records.HTTPS[domain]; exists {
			rr = &dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeHTTPS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Priority: uint16(httpsRecord.Priority),
					Target:   httpsRecord.Target,
					Value:    []dns.SVCBKeyValue{},
				},
			}
			found = true
		}

	case dns.TypeCAA:
		if caaRecord, exists := r.records.CAA[domain]; exists {
			rr = &dns.CAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Flag:  uint8(caaRecord.Flag),
				Tag:   caaRecord.Tag,
				Value: caaRecord.Value,
			}
			found = true
		}

	case dns.TypeSRV:
		if srvRecord, exists := r.records.SRV[domain]; exists {
			rr = &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: uint16(srvRecord.Priority),
				Weight:   uint16(srvRecord.Weight),
				Port:     uint16(srvRecord.Port),
				Target:   srvRecord.Target,
			}
			found = true
		}

	case dns.TypeSVCB:
		if svcbRecord, exists := r.records.SVCB[domain]; exists {
			rr = &dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeSVCB,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: uint16(svcbRecord.Priority),
				Target:   svcbRecord.Target,
				Value:    []dns.SVCBKeyValue{},
			}
			found = true
		}

	case dns.TypeDS:
		if dsRecord, exists := r.records.DS[domain]; exists {
			rr = &dns.DS{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				KeyTag:     uint16(dsRecord.KeyTag),
				Algorithm:  uint8(dsRecord.Algorithm),
				DigestType: uint8(dsRecord.DigestType),
				Digest:     dsRecord.Digest,
			}
			found = true
		}

	case dns.TypeDNSKEY:
		if dnskeyRecord, exists := r.records.DNSKEY[domain]; exists {
			rr = &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Flags:     uint16(dnskeyRecord.Flags),
				Protocol:  uint8(dnskeyRecord.Protocol),
				Algorithm: uint8(dnskeyRecord.Algorithm),
				PublicKey: dnskeyRecord.PublicKey,
			}
			found = true
		}

	case dns.TypeURI:
		if uriRecord, exists := r.records.URI[domain]; exists {
			rr = &dns.URI{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeURI,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: uint16(uriRecord.Priority),
				Weight:   uint16(uriRecord.Weight),
				Target:   uriRecord.Target,
			}
			found = true
		}

	case dns.TypeNAPTR:
		if naptrRecord, exists := r.records.NAPTR[domain]; exists {
			rr = &dns.NAPTR{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeNAPTR,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Order:       uint16(naptrRecord.Order),
				Preference:  uint16(naptrRecord.Preference),
				Flags:       naptrRecord.Flags,
				Service:     naptrRecord.Service,
				Regexp:      naptrRecord.Regexp,
				Replacement: naptrRecord.Replacement,
			}
			found = true
		}

	case dns.TypeSSHFP:
		if sshfpRecord, exists := r.records.SSHFP[domain]; exists {
			rr = &dns.SSHFP{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeSSHFP,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Algorithm:   uint8(sshfpRecord.Algorithm),
				Type:        uint8(sshfpRecord.Type),
				FingerPrint: sshfpRecord.Fingerprint,
			}
			found = true
		}

	case dns.TypeTLSA:
		if tlsaRecord, exists := r.records.TLSA[domain]; exists {
			rr = &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Usage:        uint8(tlsaRecord.Usage),
				Selector:     uint8(tlsaRecord.Selector),
				MatchingType: uint8(tlsaRecord.MatchingType),
				Certificate:  tlsaRecord.Certificate,
			}
			found = true
		}

	case dns.TypeSMIMEA:
		if smimeaRecord, exists := r.records.SMIMEA[domain]; exists {
			rr = &dns.SMIMEA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeSMIMEA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Usage:        uint8(smimeaRecord.Usage),
				Selector:     uint8(smimeaRecord.Selector),
				MatchingType: uint8(smimeaRecord.MatchingType),
				Certificate:  smimeaRecord.Certificate,
			}
			found = true
		}

	case dns.TypeCERT:
		if certRecord, exists := r.records.CERT[domain]; exists {
			rr = &dns.CERT{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCERT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Type:        uint16(certRecord.Type),
				KeyTag:      uint16(certRecord.KeyTag),
				Algorithm:   uint8(certRecord.Algorithm),
				Certificate: certRecord.Certificate,
			}
			found = true
		}
	}

	if found {
		response.Answer = append(response.Answer, rr)
		response.Rcode = dns.RcodeSuccess

		r.logger.WithFields(logrus.Fields{
			"domain": domain,
			"qtype":  dns.TypeToString[question.Qtype],
			"answer": rr.String(),
		}).Debug("local record resolved")

		return response, true
	}

	if r.hasWildcardMatch(domain, question.Qtype) {
		return r.resolveWildcard(domain, question)
	}

	return nil, false
}

func (r *LocalResolver) hasWildcardMatch(domain string, qtype uint16) bool {
	parts := strings.Split(domain, ".")

	for i := 0; i < len(parts); i++ {
		wildcard := "*." + strings.Join(parts[i+1:], ".")

		switch qtype {
		case dns.TypeA:
			if _, exists := r.records.A[wildcard]; exists {
				return true
			}
		case dns.TypeAAAA:
			if _, exists := r.records.AAAA[wildcard]; exists {
				return true
			}
		case dns.TypeCNAME:
			if _, exists := r.records.CNAME[wildcard]; exists {
				return true
			}
		case dns.TypeMX:
			if _, exists := r.records.MX[wildcard]; exists {
				return true
			}
		case dns.TypeTXT:
			if _, exists := r.records.TXT[wildcard]; exists {
				return true
			}
		}
	}

	return false
}

func (r *LocalResolver) resolveWildcard(domain string, question dns.Question) (*dns.Msg, bool) {
	parts := strings.Split(domain, ".")

	for i := range len(parts) {
		wildcard := "*." + strings.Join(parts[i+1:], ".")

		wildcardQuestion := dns.Question{
			Name:   wildcard + ".",
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}

		if response, found := r.Resolve(wildcardQuestion); found {
			for _, rr := range response.Answer {
				rr.Header().Name = question.Name
			}

			r.logger.WithFields(logrus.Fields{
				"domain":   domain,
				"wildcard": wildcard,
				"qtype":    dns.TypeToString[question.Qtype],
			}).Debug("wildcard record resolved")

			return response, true
		}
	}

	return nil, false
}
