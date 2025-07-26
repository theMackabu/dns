package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Cache    CacheConfig    `toml:"cache"`
	Upstream UpstreamConfig `toml:"upstream"`
	Logging  LoggingConfig  `toml:"logging"`
	Records  RecordsConfig  `toml:"records"`
}

type ServerConfig struct {
	Port         int           `toml:"port"`
	BindAddress  string        `toml:"bind_address"`
	ReadTimeout  time.Duration `toml:"read_timeout"`
	WriteTimeout time.Duration `toml:"write_timeout"`
}

type CacheConfig struct {
	MaxEntries      int           `toml:"max_entries"`
	DefaultTTL      time.Duration `toml:"default_ttl"`
	CleanupInterval time.Duration `toml:"cleanup_interval"`
}

type UpstreamConfig struct {
	Servers []string      `toml:"servers"`
	Timeout time.Duration `toml:"timeout"`
	Retries int           `toml:"retries"`
}

type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

type RecordsConfig struct {
	A      map[string]string       `toml:"A"`
	AAAA   map[string]string       `toml:"AAAA"`
	CNAME  map[string]string       `toml:"CNAME"`
	MX     map[string]MXRecord     `toml:"MX"`
	TXT    map[string]string       `toml:"TXT"`
	HTTPS  map[string]HTTPSRecord  `toml:"HTTPS"`
	CAA    map[string]CAARecord    `toml:"CAA"`
	SRV    map[string]SRVRecord    `toml:"SRV"`
	SVCB   map[string]SVCBRecord   `toml:"SVCB"`
	DS     map[string]DSRecord     `toml:"DS"`
	DNSKEY map[string]DNSKEYRecord `toml:"DNSKEY"`
	URI    map[string]URIRecord    `toml:"URI"`
	NAPTR  map[string]NAPTRRecord  `toml:"NAPTR"`
	SSHFP  map[string]SSHFPRecord  `toml:"SSHFP"`
	TLSA   map[string]TLSARecord   `toml:"TLSA"`
	SMIMEA map[string]SMIMEARecord `toml:"SMIMEA"`
	CERT   map[string]CERTRecord   `toml:"CERT"`
}

type MXRecord struct {
	Priority int    `toml:"priority"`
	Target   string `toml:"target"`
}

type HTTPSRecord struct {
	Priority int    `toml:"priority"`
	Target   string `toml:"target"`
	Params   string `toml:"params"`
}

type CAARecord struct {
	Flag  int    `toml:"flag"`
	Tag   string `toml:"tag"`
	Value string `toml:"value"`
}

type SRVRecord struct {
	Priority int    `toml:"priority"`
	Weight   int    `toml:"weight"`
	Port     int    `toml:"port"`
	Target   string `toml:"target"`
}

type SVCBRecord struct {
	Priority int    `toml:"priority"`
	Target   string `toml:"target"`
	Params   string `toml:"params"`
}

type DSRecord struct {
	KeyTag     int    `toml:"keytag"`
	Algorithm  int    `toml:"algorithm"`
	DigestType int    `toml:"digesttype"`
	Digest     string `toml:"digest"`
}

type DNSKEYRecord struct {
	Flags     int    `toml:"flags"`
	Protocol  int    `toml:"protocol"`
	Algorithm int    `toml:"algorithm"`
	PublicKey string `toml:"publickey"`
}

type URIRecord struct {
	Priority int    `toml:"priority"`
	Weight   int    `toml:"weight"`
	Target   string `toml:"target"`
}

type NAPTRRecord struct {
	Order       int    `toml:"order"`
	Preference  int    `toml:"preference"`
	Flags       string `toml:"flags"`
	Service     string `toml:"service"`
	Regexp      string `toml:"regexp"`
	Replacement string `toml:"replacement"`
}

type SSHFPRecord struct {
	Algorithm   int    `toml:"algorithm"`
	Type        int    `toml:"type"`
	Fingerprint string `toml:"fingerprint"`
}

type TLSARecord struct {
	Usage        int    `toml:"usage"`
	Selector     int    `toml:"selector"`
	MatchingType int    `toml:"matchingtype"`
	Certificate  string `toml:"certificate"`
}

type SMIMEARecord struct {
	Usage        int    `toml:"usage"`
	Selector     int    `toml:"selector"`
	MatchingType int    `toml:"matchingtype"`
	Certificate  string `toml:"certificate"`
}

type CERTRecord struct {
	Type        int    `toml:"type"`
	KeyTag      int    `toml:"keytag"`
	Algorithm   int    `toml:"algorithm"`
	Certificate string `toml:"certificate"`
}

type ConfigLoader interface {
	Load(path string) (*Config, error)
}

type TOMLConfigLoader struct{}

func NewTOMLConfigLoader() *TOMLConfigLoader {
	return &TOMLConfigLoader{}
}

func (l *TOMLConfigLoader) Load(path string) (*Config, error) {
	config := &Config{}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return l.defaultConfig(), nil
	}

	if _, err := toml.DecodeFile(path, config); err != nil {
		return nil, fmt.Errorf("failed to decode config file %s: %w", path, err)
	}

	if err := l.validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	l.setDefaults(config)
	return config, nil
}

func (l *TOMLConfigLoader) defaultConfig() *Config {
	config := &Config{
		Server: ServerConfig{
			Port:         53,
			BindAddress:  "0.0.0.0",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Cache: CacheConfig{
			MaxEntries:      10000,
			DefaultTTL:      300 * time.Second,
			CleanupInterval: 60 * time.Second,
		},
		Upstream: UpstreamConfig{
			Servers: []string{"8.8.8.8:53", "1.1.1.1:53"},
			Timeout: 2 * time.Second,
			Retries: 3,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Records: RecordsConfig{
			A:     make(map[string]string),
			AAAA:  make(map[string]string),
			CNAME: make(map[string]string),
			MX:    make(map[string]MXRecord),
			TXT:   make(map[string]string),
		},
	}
	return config
}

func (l *TOMLConfigLoader) validate(config *Config) error {
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Cache.MaxEntries < 1 {
		return fmt.Errorf("cache max_entries must be positive: %d", config.Cache.MaxEntries)
	}

	if len(config.Upstream.Servers) == 0 {
		return fmt.Errorf("at least one upstream server must be configured")
	}

	if config.Upstream.Retries < 0 {
		return fmt.Errorf("upstream retries must be non-negative: %d", config.Upstream.Retries)
	}

	if err := l.validateRecords(config); err != nil {
		return fmt.Errorf("invalid records configuration: %w", err)
	}

	return nil
}

func (l *TOMLConfigLoader) validateRecords(config *Config) error {
	for domain, ip := range config.Records.A {
		if !l.isValidDomain(domain) {
			return fmt.Errorf("invalid A record domain: %s", domain)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid A record IP for %s: %s", domain, ip)
		}
	}

	for domain, ip := range config.Records.AAAA {
		if !l.isValidDomain(domain) {
			return fmt.Errorf("invalid AAAA record domain: %s", domain)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid AAAA record IP for %s: %s", domain, ip)
		}
	}

	for domain, target := range config.Records.CNAME {
		if !l.isValidDomain(domain) {
			return fmt.Errorf("invalid CNAME record domain: %s", domain)
		}
		if !l.isValidDomain(target) {
			return fmt.Errorf("invalid CNAME record target for %s: %s", domain, target)
		}
	}

	for domain, mx := range config.Records.MX {
		if !l.isValidDomain(domain) {
			return fmt.Errorf("invalid MX record domain: %s", domain)
		}
		if !l.isValidDomain(mx.Target) {
			return fmt.Errorf("invalid MX record target for %s: %s", domain, mx.Target)
		}
		if mx.Priority < 0 || mx.Priority > 65535 {
			return fmt.Errorf("invalid MX record priority for %s: %d", domain, mx.Priority)
		}
	}

	return nil
}

func (l *TOMLConfigLoader) isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	for part := range strings.SplitSeq(strings.TrimSuffix(domain, "."), ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}

	return true
}

func (l *TOMLConfigLoader) setDefaults(config *Config) {
	if config.Server.Port == 0 {
		config.Server.Port = 53
	}
	if config.Server.BindAddress == "" {
		config.Server.BindAddress = "0.0.0.0"
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 5 * time.Second
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 5 * time.Second
	}
	if config.Cache.MaxEntries == 0 {
		config.Cache.MaxEntries = 10000
	}
	if config.Cache.DefaultTTL == 0 {
		config.Cache.DefaultTTL = 300 * time.Second
	}
	if config.Cache.CleanupInterval == 0 {
		config.Cache.CleanupInterval = 60 * time.Second
	}
	if len(config.Upstream.Servers) == 0 {
		config.Upstream.Servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if config.Upstream.Timeout == 0 {
		config.Upstream.Timeout = 2 * time.Second
	}
	if config.Upstream.Retries == 0 {
		config.Upstream.Retries = 3
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}
	if config.Records.A == nil {
		config.Records.A = make(map[string]string)
	}
	if config.Records.AAAA == nil {
		config.Records.AAAA = make(map[string]string)
	}
	if config.Records.CNAME == nil {
		config.Records.CNAME = make(map[string]string)
	}
	if config.Records.MX == nil {
		config.Records.MX = make(map[string]MXRecord)
	}
	if config.Records.TXT == nil {
		config.Records.TXT = make(map[string]string)
	}
}
