package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/auth"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/jwt"
	"github.com/grepplabs/loggo/zlog"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/grepplabs/casbin-traefik-forward-auth/internal/config"
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

// nolint: funlen
func buildEngine(cfg config.Config) (*gin.Engine, Closers, error) {
	closers := make(Closers, 0)

	gin.SetMode(gin.ReleaseMode)

	engineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "main"))
	engine := gin.New()
	engine.Use(ginzap.GinzapWithConfig(engineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{"/healthz", "/readyz", "/metrics"},
	}))
	engine.Use(ginzap.RecoveryWithZap(engineLogger, true))
	ginprometheus.NewWithConfig(ginprometheus.Config{
		DisableBodyReading: true,
	}).Use(engine)

	authEngineLogger := zlog.LogSink.WithOptions(zap.WithCaller(false)).With(zap.String("engine", "auth"))
	authEngine := gin.New()
	authEngine.Use(ginzap.GinzapWithConfig(authEngineLogger, &ginzap.Config{
		TimeFormat: time.RFC3339,
	}))
	authEngine.Use(ginzap.RecoveryWithZap(authEngineLogger, true))
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
	engine.GET("/healthz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	engine.GET("/readyz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	zlog.Infof("starting enforcer")
	err = enforcer.Start(context.Background())
	if err != nil {
		return nil, closers, fmt.Errorf("error starting enforcer: %w", err)
	}
	return engine, closers, nil
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
	engine, closers, err := buildEngine(cfg)
	defer func() { _ = closers.Close() }()
	if err != nil {
		return fmt.Errorf("error building engine: %w", err)
	}
	zlog.Infof("starting server on %s (version: %s)", cfg.Server.Addr, getVersion())
	return engine.Run(cfg.Server.Addr)
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
