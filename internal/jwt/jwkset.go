package jwt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	tlsclient "github.com/grepplabs/cert-source/tls/client"
	tlsclientconfig "github.com/grepplabs/cert-source/tls/client/config"
	"github.com/grepplabs/loggo/zlog"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/tracesink"
	"github.com/lestrrat-go/jwx/v3/jwk"
	slogzap "github.com/samber/slog-zap/v2"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
)

func newJWKSet(ctx context.Context, config config.JWTConfig) (jwk.Set, error) {
	if strings.EqualFold(config.JWKSURL, "none") {
		return jwk.NewSet(), nil
	}
	if isFileSet(&config) {
		return newFileJWKSet(config)
	}
	if _, err := url.ParseRequestURI(config.JWKSURL); err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %w", err)
	}
	return newHttpJWKSet(ctx, config)
}

func isFileSet(config *config.JWTConfig) bool {
	return !strings.HasPrefix(config.JWKSURL, "http://") && !strings.HasPrefix(config.JWKSURL, "https://")
}

func newHttpJWKSet(ctx context.Context, config config.JWTConfig) (jwk.Set, error) {
	clientOptions := []httprc.NewClientOption{httprc.WithTraceSink(tracesink.NewSlog(newZapSlogLogger()))}
	if config.TLS.Enable && strings.HasPrefix(config.JWKSURL, "https://") {
		httpClient, err := newHTTPClientForJWKS(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create http client for jwks: %w", err)
		}
		clientOptions = append(clientOptions, httprc.WithHTTPClient(httpClient))
	}
	c, err := jwk.NewCache(
		ctx,
		httprc.NewClient(clientOptions...),
	)
	if err != nil {
		return nil, fmt.Errorf("create jwk set: %w", err)
	}
	zlog.Infof("registering new jwk cache for %s", config.JWKSURL)

	err = c.Register(ctx, config.JWKSURL,
		jwk.WithMaxInterval(config.MaxRefreshInterval),
		jwk.WithMinInterval(config.MinRefreshInterval),
		jwk.WithWaitReady(false), // register non-blocking
	)
	if err != nil {
		return nil, fmt.Errorf("register jwk set: %w", err)
	}

	if err := waitForJWKRefresh(ctx, c, config); err != nil {
		return nil, fmt.Errorf("initial jwks fetch failed for %s: %w", config.JWKSURL, err)
	}

	cached, err := c.CachedSet(config.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("cache jwk set: %w", err)
	}
	return cached, nil
}

func newHTTPClientForJWKS(cfg config.JWTConfig) (*http.Client, error) {
	sl := slog.New(slogzap.Option{Logger: zlog.LogSink}.NewZapHandler())
	tlsClientConfigFunc, err := tlsclientconfig.GetTLSClientConfigFunc(sl, &cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("create tls client config: %w", err)
	}
	transport := tlsclient.NewDefaultRoundTripper(tlsclient.WithClientTLSConfig(tlsClientConfigFunc()))
	client := &http.Client{Transport: transport}
	return client, nil
}

func waitForJWKRefresh(ctx context.Context, cache *jwk.Cache, config config.JWTConfig) error {
	totalTimeout := config.InitTimeout
	if totalTimeout <= 0 {
		totalTimeout = 60 * time.Second
	}
	perCallTimeout := config.RefreshTimeout
	if perCallTimeout <= 0 {
		perCallTimeout = 5 * time.Second
	}

	deadline := time.Now().Add(totalTimeout)
	var (
		lastErr     error
		refreshTick = 500 * time.Millisecond
	)

	for {
		callCtx, cancel := context.WithTimeout(ctx, perCallTimeout)
		_, err := cache.Refresh(callCtx, config.JWKSURL)
		cancel()
		if err == nil {
			if cached, err := cache.CachedSet(config.JWKSURL); err == nil && cached.Len() > 0 {
				return nil
			}
			lastErr = errors.New("jwks cache still empty after refresh")
		} else {
			lastErr = fmt.Errorf("refresh failed: %w", err)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf(
				"initial jwks fetch failed for %s after %s: %w",
				config.JWKSURL, totalTimeout, lastErr,
			)
		}
		timer := time.NewTimer(refreshTick)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("initial jwks fetch aborted: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func newFileJWKSet(config config.JWTConfig) (jwk.Set, error) {
	path := strings.TrimPrefix(config.JWKSURL, "file://")

	options := make([]jwk.ReadFileOption, 0)
	if config.UseX509 {
		options = append(options, jwk.WithX509(true))
	}
	jwks, err := jwk.ReadFile(path, options...)
	if err != nil {
		return nil, fmt.Errorf("read jwk set: %w", err)
	}
	return jwks, nil
}

type zapSlogLogger struct{}

func newZapSlogLogger() *zapSlogLogger {
	return &zapSlogLogger{}
}

func (l *zapSlogLogger) Log(_ context.Context, level slog.Level, msg string, args ...any) {
	switch {
	case level <= slog.LevelDebug:
		zlog.Debugf(msg, args...)
	case level <= slog.LevelInfo:
		zlog.Infof(msg, args...)
	case level <= slog.LevelWarn:
		zlog.Warnf(msg, args...)
	default:
		zlog.Errorf(msg, args...)
	}
}
