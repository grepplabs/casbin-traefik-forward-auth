package config

import (
	"errors"
	"fmt"
	"time"

	casbinkube "github.com/grepplabs/casbin-kube"
	tlsconfig "github.com/grepplabs/cert-source/config"
)

var (
	// Version is the current version of the app, generated at build time
	Version = "unknown"
)

const (
	AdapterFile = "file"
	AdapterKube = "kube"
)

type AuthHeaderSource = string

const (
	AuthHeaderSourceAuto      AuthHeaderSource = "auto"
	AuthHeaderSourceForwarded AuthHeaderSource = "forwarded"
	AuthHeaderSourceOriginal  AuthHeaderSource = "original"
)

type ServerConfig struct {
	Addr      string
	AdminPort int
	TLS       tlsconfig.TLSServerConfig
}
type Config struct {
	Server  ServerConfig
	Casbin  CasbinConfig
	Auth    AuthConfig
	Metrics MetricsConfig
}

type MetricsConfig struct {
	IncludeHost bool
}

type AuthConfig struct {
	RouteConfigPath string
	JWTConfig       JWTConfig
	HeaderSource    AuthHeaderSource
}

type CasbinConfig struct {
	Model                  string // if starts file:// then load from disk
	AutoLoadPolicyInterval time.Duration
	Adapter                string // adapter type: kube or file
	AdapterKube            CasbinAdapterKubeConfig
	AdapterFile            CasbinAdapterFileConfig
}

type CasbinAdapterKubeConfig struct {
	DisableInformer bool
	casbinkube.KubeConfig
}

type CasbinAdapterFileConfig struct {
	PolicyPath string
}

type JWTConfig struct {
	// Enables or disables JWT validation
	Enabled bool

	// URL to the JWKS endpoint, e.g. "https://issuer.example.com/.well-known/jwks.json"
	JWKSURL string

	// Expected issuer ("iss" claim)
	Issuer string

	// Expected audience ("aud" claim)
	Audience string

	// Optional clock skew tolerance for exp/nbf/etc. e.g. 30 * time.Second. Zero means "no extra skew".
	Skew time.Duration

	// Specifies how long to wait for the initial JWKS retrieval during startup or registration before timing out.
	InitTimeout time.Duration

	// RefreshTimeout specifies the maximum duration allowed for each individual
	// JWKS refresh HTTP request (both during initial fetch and background updates).
	RefreshTimeout time.Duration

	// MinRefreshInterval specifies the minimum duration between JWKS refresh attempts.
	MinRefreshInterval time.Duration

	// MaxRefreshInterval specifies the maximum duration between JWKS refresh attempts.
	MaxRefreshInterval time.Duration

	// UseX509 indicates whether the JWKS file contains X.509-encoded keys (e.g., PEM certificates)
	// instead of standard JWK JSON. When set to true, the file will be read and parsed as X.509.
	UseX509 bool

	// TLS config for the HTTPS client used to fetch the JWKS.
	TLS tlsconfig.TLSClientConfig
}

func (c *JWTConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.JWKSURL == "" {
		return errors.New("jwt-jwks-url must be set when JWT validation is enabled")
	}
	if c.Issuer == "" {
		return errors.New("jwt-issuer must be set when JWT validation is enabled")
	}
	if c.Audience == "" {
		return errors.New("jwt-audience must be set when JWT validation is enabled")
	}
	return nil
}

func (a *AuthConfig) Validate() error {
	switch a.HeaderSource {
	case AuthHeaderSourceAuto, AuthHeaderSourceForwarded, AuthHeaderSourceOriginal:
		// ok
	default:
		return fmt.Errorf(
			"invalid auth-header-source %q (expected one of: %q, %q, %q)",
			a.HeaderSource,
			AuthHeaderSourceForwarded,
			AuthHeaderSourceOriginal,
			AuthHeaderSourceAuto,
		)
	}
	if a.JWTConfig.Enabled {
		if err := a.JWTConfig.Validate(); err != nil {
			return fmt.Errorf("invalid JWT config: %w", err)
		}
	}
	return nil
}
