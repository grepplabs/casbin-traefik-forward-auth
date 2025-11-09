package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-forward-auth/internal/auth"
	"github.com/grepplabs/casbin-forward-auth/internal/jwt"
	"github.com/grepplabs/casbin-forward-auth/internal/metrics"
	tlsserverconfig "github.com/grepplabs/cert-source/tls/server/config"
	"github.com/grepplabs/loggo/zlog"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	slogzap "github.com/samber/slog-zap/v2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
)

const (
	HeaderForwardedMethod = "X-Forwarded-Method"
	HeaderForwardedProto  = "X-Forwarded-Proto"
	HeaderForwardedHost   = "X-Forwarded-Host"
	HeaderForwardedURI    = "X-Forwarded-Uri"
	HeaderForwardedFor    = "X-Forwarded-For"
	HeaderHost            = "Host"
	HeaderWWWAuthenticate = "WWW-Authenticate"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

// nolint: funlen, cyclop
func buildEngine(registry *prometheus.Registry, cfg config.Config) (*gin.Engine, Closers, error) {
	closers := make(Closers, 0)

	gin.SetMode(gin.ReleaseMode)

	mainMetricsMW, err := metrics.NewMiddlewareWithConfig(metrics.MiddlewareConfig{
		Namespace:   "main",
		Registerer:  registry,
		IncludeHost: cfg.Metrics.IncludeHost,
	})
	if err != nil {
		return nil, closers, fmt.Errorf("creating main metrics middleware: %w", err)
	}
	authMetricsMW, err := metrics.NewMiddlewareWithConfig(metrics.MiddlewareConfig{
		Namespace:   "auth",
		Registerer:  registry,
		IncludeHost: cfg.Metrics.IncludeHost,
	})
	if err != nil {
		return nil, closers, fmt.Errorf("creating auth metrics middleware: %w", err)
	}

	engineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "main"))
	engine := gin.New()
	engine.Use(ginzap.GinzapWithConfig(engineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{"/healthz", "/readyz", "/metrics"},
	}))
	engine.Use(ginzap.RecoveryWithZap(engineLogger, true))
	engine.Use(metrics.GinMiddleware(mainMetricsMW))

	authEngineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "auth"))
	authEngine := gin.New()
	authEngine.Use(ginzap.GinzapWithConfig(authEngineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
	}))
	authEngine.Use(ginzap.RecoveryWithZap(authEngineLogger, true))
	authEngine.Use(metrics.GinMiddleware(authMetricsMW))
	if cfg.Auth.JWTConfig.Enabled {
		if err := cfg.Auth.JWTConfig.Validate(); err != nil {
			return nil, closers, fmt.Errorf("invalid JWT config: %w", err)
		}
		verifier, err := jwt.NewJWTVerifier(context.Background(), cfg.Auth.JWTConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("invalid JWT verifier: %w", err)
		}
		closers.Add(verifier)
		authEngine.Use(verifier.Middleware())
	}

	enforcer, err := newLifecycleEnforcer(&cfg.Casbin)
	if err != nil {
		return nil, closers, fmt.Errorf("could not create enforcer: %w", err)
	}
	closers.Add(enforcer)

	var (
		routeConfig *auth.RouteConfig
	)
	if cfg.Auth.RouteConfigPath != "" {
		routeConfig, err = loadRouteConfig(cfg.Auth.RouteConfigPath)
		if err != nil {
			return nil, closers, fmt.Errorf("error loading route config: %w", err)
		}
	} else {
		zlog.Warnf("auth-route-config-path is not provided")
		routeConfig = &auth.RouteConfig{}
	}
	auth.SetupRoutes(authEngine, routeConfig.Routes, enforcer.SyncedEnforcer)

	engine.GET("/v1/auth", authHandler(authEngine))

	if cfg.Server.AdminPort == 0 {
		addAdminEndpoints(registry, engine)
	}
	zlog.Infof("starting enforcer")
	err = enforcer.Start(context.Background())
	if err != nil {
		return nil, closers, fmt.Errorf("error starting enforcer: %w", err)
	}
	return engine, closers, nil
}

func newRegistry() *prometheus.Registry {
	registerer := prometheus.NewRegistry()
	registerer.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return registerer
}

func buildAdminEngine(registry *prometheus.Registry) *gin.Engine {
	engineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "admin"))
	engine := gin.New()
	engine.Use(ginzap.GinzapWithConfig(engineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{"/healthz", "/readyz", "/metrics"},
	}))
	engine.Use(ginzap.RecoveryWithZap(engineLogger, true))
	addAdminEndpoints(registry, engine)
	return engine
}

func getAdminAddr(cfg config.Config) (string, error) {
	addr := cfg.Server.Addr
	if addr == "" {
		return "", errors.New("server address cannot be empty")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// handle cases like ":8080" or invalid formats
		if strings.HasPrefix(addr, ":") {
			host = ""
		} else {
			return "", fmt.Errorf("invalid server address %q: %w", addr, err)
		}
	}
	adminAddr := net.JoinHostPort(host, strconv.Itoa(cfg.Server.AdminPort))
	return adminAddr, nil
}

func addAdminEndpoints(registry *prometheus.Registry, engine *gin.Engine) {
	engine.GET("/healthz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	engine.GET("/readyz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	engine.GET("/metrics", metrics.NewHandlerWithConfig(metrics.HandlerConfig{
		Gatherer: registry,
	}))
}

func authHandler(authEngine *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		reason, headers, err := forwardAuth(c, authEngine)
		if err == nil {
			c.String(http.StatusOK, reason)
			return
		}

		if errors.Is(err, ErrUnauthorized) {
			for key, values := range headers {
				for _, value := range values {
					c.Writer.Header().Add(key, value)
				}
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}
}

func Start(cfg config.Config) error {
	registry := newRegistry()
	engine, closers, err := buildEngine(registry, cfg)
	defer func() { _ = closers.Close() }()
	if err != nil {
		return fmt.Errorf("error building engine: %w", err)
	}
	var group run.Group
	group.Add(func() error {
		if cfg.Server.TLS.Enable {
			sl := slog.New(slogzap.Option{Logger: zlog.LogSink}.NewZapHandler())
			tlsConfig, err := tlsserverconfig.GetServerTLSConfig(sl, &cfg.Server.TLS)
			if err != nil {
				return fmt.Errorf("error creating TLS server config: %w", err)
			}
			//nolint:noctx
			ln, err := net.Listen("tcp", cfg.Server.Addr)
			if err != nil {
				return fmt.Errorf("error listening on %s: %w", cfg.Server.Addr, err)
			}
			tlsLn := tls.NewListener(ln, tlsConfig)

			zlog.Infof("starting TLS server on %s (version: %s)", cfg.Server.Addr, getVersion())
			return engine.RunListener(tlsLn)
		} else {
			zlog.Infof("starting server on %s (version: %s)", cfg.Server.Addr, getVersion())
			return engine.Run(cfg.Server.Addr)
		}
	}, func(err error) {
	})

	if cfg.Server.AdminPort > 0 {
		adminAddr, err := getAdminAddr(cfg)
		if err != nil {
			return fmt.Errorf("error getting admin address: %w", err)
		}
		adminEngine := buildAdminEngine(registry)

		group.Add(func() error {
			zlog.Infof("starting admin server %s", adminAddr)
			return adminEngine.Run(adminAddr)
		}, func(err error) {
		})
	}
	return group.Run()
}

func getVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return config.Version
}

func loadRouteConfig(path string) (*auth.RouteConfig, error) {
	// #nosec G304 -- path is controlled and provided as config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg auth.RouteConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err = cfg.Validate(); err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("error marshalling route config: %w", err)
	}
	zlog.Infof("route config:\n" + string(b))
	return &cfg, nil
}

func forwardAuth(c *gin.Context, authEngine *gin.Engine) (string, http.Header, error) {
	forwardedUri := c.GetHeader(HeaderForwardedURI)
	forwardedMethod := c.GetHeader(HeaderForwardedMethod)
	forwardedHost := c.GetHeader(HeaderForwardedHost)
	if forwardedUri == "" || forwardedMethod == "" || forwardedHost == "" {
		return "", nil, errors.New("missing auth headers")
	}
	lw := zlog.Logger.WithValues("method", forwardedMethod, "host", forwardedHost, "uri", forwardedUri)
	lw.V(1).Info("forward auth")

	req, err := http.NewRequestWithContext(c, forwardedMethod, forwardedUri, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.RemoteAddr = c.Request.RemoteAddr

	// copy all headers
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	// delete traefik headers
	req.Header.Del(HeaderForwardedMethod)
	req.Header.Del(HeaderForwardedProto)
	req.Header.Del(HeaderForwardedHost)
	req.Header.Del(HeaderForwardedURI)
	req.Header.Del(HeaderForwardedFor)

	// set original host
	req.Host = forwardedHost
	req.Header.Set(HeaderHost, forwardedHost)

	w := httptest.NewRecorder()
	authEngine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		lw.V(1).Info("forward auth rejected", "code", w.Code)
		if w.Code == http.StatusUnauthorized {
			resHeaders := make(http.Header)
			hv := w.Header().Values(HeaderWWWAuthenticate)
			if len(hv) > 0 {
				resHeaders.Add(HeaderWWWAuthenticate, hv[0])
			}
			return "", resHeaders, fmt.Errorf("%w: %s", ErrUnauthorized, w.Body.String())
		}
		return "", nil, errors.New(w.Body.String())
	}
	return w.Body.String(), nil, nil
}
