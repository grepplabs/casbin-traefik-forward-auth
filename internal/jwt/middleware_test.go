package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("disabled jwt -> allows request without auth header", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cfg := config.JWTConfig{
			Enabled: false,
		}

		verifier, err := NewJWTVerifier(ctx, cfg)
		require.NoError(t, err)
		defer verifier.Close()

		router := gin.New()
		router.Use(verifier.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	})

	t.Run("enabled jwt -> missing bearer token returns 401 and aborts chain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tmpDir := t.TempDir()
		publicPath := filepath.Join(tmpDir, "public.jwks.json")

		_, pubSet, err := generateJWKS("", publicPath)
		require.NoError(t, err)
		require.Equal(t, 1, pubSet.Len())

		cfg := config.JWTConfig{
			Enabled:     true,
			JWKSURL:     "file://" + publicPath,
			InitTimeout: 5 * time.Second,
			Issuer:      "https://issuer.example.internal",
			Audience:    "my-audience",
			UseX509:     false,
		}

		verifier, err := NewJWTVerifier(ctx, cfg)
		require.NoError(t, err)
		defer verifier.Close()

		router := gin.New()
		router.Use(verifier.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `Bearer realm="https://issuer.example.internal", error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
		assert.Contains(t, w.Body.String(), `"error":"missing or malformed bearer token"`)
	})

	t.Run("enabled jwt -> invalid bearer token returns 401", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tmpDir := t.TempDir()
		publicPath := filepath.Join(tmpDir, "public.jwks.json")

		_, pubSet, err := generateJWKS("", publicPath)
		require.NoError(t, err)
		require.Equal(t, 1, pubSet.Len())

		cfg := config.JWTConfig{
			Enabled:     true,
			JWKSURL:     "file://" + publicPath,
			InitTimeout: 5 * time.Second,
			Issuer:      "https://issuer.example.internal",
			Audience:    "my-audience",
			UseX509:     false,
		}

		verifier, err := NewJWTVerifier(ctx, cfg)
		require.NoError(t, err)
		defer verifier.Close()

		router := gin.New()
		router.Use(verifier.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer abc")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `Bearer realm="https://issuer.example.internal", error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
		assert.Contains(t, w.Body.String(), `"error":"invalid token"`)
		assert.Contains(t, w.Body.String(), `"details":`)
	})

	t.Run("enabled jwt -> valid token allows request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tmpDir := t.TempDir()
		publicPath := filepath.Join(tmpDir, "public.jwks.json")

		privSet, pubSet, err := generateJWKS("", publicPath)
		require.NoError(t, err)
		require.Equal(t, 1, privSet.Len())
		require.Equal(t, 1, pubSet.Len())

		cfg := config.JWTConfig{
			Enabled:     true,
			JWKSURL:     "file://" + publicPath,
			InitTimeout: 5 * time.Second,
			Issuer:      "https://issuer.example.internal",
			Audience:    "my-audience",
			UseX509:     false,
		}

		verifier, err := NewJWTVerifier(ctx, cfg)
		require.NoError(t, err)
		defer verifier.Close()

		privKey, ok := privSet.Key(0)
		require.True(t, ok)

		signedJWT, err := signToken("alice", privKey, cfg)
		require.NoError(t, err)

		router := gin.New()
		router.Use(verifier.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+signedJWT)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	})
}

func TestExtractBearerToken(t *testing.T) {
	t.Run("valid bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer token-value")

		token, err := extractBearerToken(req)
		require.NoError(t, err)
		assert.Equal(t, "token-value", token)
	})

	t.Run("valid bearer lowercase", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "bearer abc123")

		token, err := extractBearerToken(req)
		require.NoError(t, err)
		assert.Equal(t, "abc123", token)
	})

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)

		token, err := extractBearerToken(req)
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Equal(t, errNoTokenInRequest, err)
	})

	t.Run("not bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Basic xyz")

		token, err := extractBearerToken(req)
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Equal(t, errNoTokenInRequest, err)
	})
}
