package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	errNoTokenInRequest = errors.New("no bearer token in request")
)

type Verifier struct {
	cfg    *config.JWTConfig
	keySet jwk.Set
	cancel context.CancelFunc
}

func NewJWTVerifier(ctx context.Context, cfg config.JWTConfig) (*Verifier, error) {
	_, cancel := context.WithCancel(ctx)

	if !cfg.Enabled {
		return &Verifier{
			cfg:    &cfg,
			keySet: jwk.NewSet(),
			cancel: cancel,
		}, nil
	}

	keySet, err := newJWKSet(ctx, cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("init jwk set: %w", err)
	}
	return &Verifier{
		cfg:    &cfg,
		keySet: keySet,
		cancel: cancel,
	}, nil
}

func (v *Verifier) Close() error {
	if v.cancel != nil {
		v.cancel()
	}
	return nil
}

func (v *Verifier) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !v.cfg.Enabled {
			c.Next()
			return
		}
		signedJWT, err := extractBearerToken(c.Request)
		if err != nil {
			v.unauthorized(c, err, "missing or malformed bearer token")
			return
		}
		_, err = verifyToken(signedJWT, v.cfg, v.keySet)
		if err != nil {
			v.unauthorized(c, err, "invalid token")
			return
		}
		c.Next()
	}
}

func extractBearerToken(req *http.Request) (string, error) {
	tokenHeader := req.Header.Get("Authorization")
	if len(tokenHeader) < 7 || !strings.EqualFold(tokenHeader[:7], "bearer ") {
		return "", errNoTokenInRequest
	}
	return tokenHeader[7:], nil
}

func (v *Verifier) unauthorized(c *gin.Context, cause error, msg string) {
	c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", error="invalid_token"`, v.cfg.Issuer))
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   msg,
		"details": cause.Error(),
	})
}
