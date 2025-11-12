package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grepplabs/casbin-forward-auth/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fileModeUserRW = 0o600 // rw-------
)

func Test_forwardAuth_MissingHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// attach a request (no forwarded header set)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth", nil)

	_, headers, err := forwardAuth(c, authEngine, config.AuthHeaderSourceAuto)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingForwardAuthHeaders)
	require.Empty(t, headers)
}

func Test_forwardAuth_HappyPath_StripsForwardedHeaders_SetsMethodAndURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seen struct {
		method string
		uri    string
		host   string
		header http.Header
	}

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		seen.method = c.Request.Method
		seen.uri = c.Request.URL.RequestURI()
		seen.host = c.Request.Host
		seen.header = c.Request.Header.Clone()
		c.String(http.StatusOK, "allowed")
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)

	req.Header.Set(HeaderForwardedMethod, http.MethodPost)
	req.Header.Set(HeaderForwardedHost, "svc.local")
	req.Header.Set(HeaderForwardedURI, "/target/path?q=1")
	req.Header.Set(HeaderForwardedProto, "http")
	req.Header.Set(HeaderForwardedFor, "1.2.3.4")
	req.Header.Set("X-Custom", "abc")
	c.Request = req

	body, headers, err := forwardAuth(c, authEngine, config.AuthHeaderSourceAuto)
	require.NoError(t, err)
	assert.Equal(t, "allowed", body)
	require.Empty(t, headers)

	assert.Equal(t, http.MethodPost, seen.method)
	assert.Equal(t, "/target/path?q=1", seen.uri)

	assert.Empty(t, seen.header.Get(HeaderForwardedMethod))
	assert.Empty(t, seen.header.Get(HeaderForwardedProto))
	assert.Empty(t, seen.header.Get(HeaderForwardedHost))
	assert.Empty(t, seen.header.Get(HeaderForwardedURI))
	assert.Empty(t, seen.header.Get(HeaderForwardedFor))

	assert.Equal(t, "abc", seen.header.Get("X-Custom"))
	assert.Equal(t, "svc.local", seen.host)
	assert.Equal(t, "svc.local", seen.header.Get(HeaderHost))
}

// nolint: canonicalheader
func Test_forwardAuth_HappyPath_NginxAuthRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seen struct {
		method string
		uri    string
		host   string
		header http.Header
	}

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) {
		seen.method = c.Request.Method
		seen.uri = c.Request.URL.RequestURI()
		seen.host = c.Request.Host
		seen.header = c.Request.Header.Clone()
		c.String(http.StatusOK, "allowed")
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)

	// nginx ingress auth_request-style headers
	req.Header.Set("X-Original-URI", "/get")
	req.Header.Set("X-Original-Method", http.MethodGet)
	req.Header.Set("X-Original-URL", "http://echo.127.0.0.1.nip.io:30180/get")
	req.Header.Set("X-Sent-From", "nginx-ingress-controller")
	req.Header.Set("X-Real-IP", "10.244.0.1")
	req.Header.Set("X-Forwarded-For", "10.244.0.1")
	req.Header.Set("X-Auth-Request-Redirect", "/get")
	req.Header.Set("Host", "casbin-auth-rbac.casbin-auth.svc.cluster.local")

	c.Request = req

	body, headers, err := forwardAuth(c, authEngine, config.AuthHeaderSourceAuto)
	require.NoError(t, err)
	assert.Equal(t, "allowed", body)
	require.Empty(t, headers)

	assert.Equal(t, http.MethodGet, seen.method)
	assert.Equal(t, "/get", seen.uri)

	assert.Equal(t, "echo.127.0.0.1.nip.io:30180", seen.host)
	assert.Empty(t, seen.header.Get("X-Original-URI"))
	assert.Empty(t, seen.header.Get("X-Original-Method"))
	assert.Empty(t, seen.header.Get("X-Original-URL"))
	assert.Empty(t, seen.header.Get("X-Forwarded-For"))
	assert.Equal(t, "10.244.0.1", seen.header.Get("X-Real-IP"))
}

func Test_loadRouteConfig_ValidMinimal(t *testing.T) {
	yml := []byte(`
routes:
  - httpMethod: GET
    relativePaths:
      - /health
`)

	dir := t.TempDir()
	p := filepath.Join(dir, "routes.yaml")
	require.NoError(t, os.WriteFile(p, yml, fileModeUserRW))

	cfg, err := loadRouteConfig(p)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Routes, 1)
	assert.Equal(t, "GET", cfg.Routes[0].HttpMethod)
	assert.Equal(t, []string{"/health"}, cfg.Routes[0].RelativePaths)
}

func Test_loadRouteConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	bad := []byte(":\n- [")
	require.NoError(t, os.WriteFile(p, bad, fileModeUserRW))

	cfg, err := loadRouteConfig(p)
	require.Error(t, err)
	assert.Nil(t, cfg)
}

func Test_loadRouteConfig_InvalidYAML_ValidateError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad-schema.yaml")

	yml := []byte(`
routes:
  - httpMethod: WRONG
    relativePaths: ["/x"]
`)
	require.NoError(t, os.WriteFile(p, yml, fileModeUserRW))

	cfg, err := loadRouteConfig(p)
	require.Error(t, err, "expected validation error for httpMethod oneof")
	assert.Nil(t, cfg)
}

func Test_forwardAuth_RejectsWhenAuthEngineReturnsNonOK(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authEngine := gin.New()
	authEngine.Any("/*any", func(c *gin.Context) { // <-- wildcard
		c.String(http.StatusForbidden, "is forbidden")
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
	req.Header.Set(HeaderForwardedMethod, http.MethodGet)
	req.Header.Set(HeaderForwardedHost, "svc.local")
	req.Header.Set(HeaderForwardedURI, "/deny")
	c.Request = req

	_, headers, err := forwardAuth(c, authEngine, config.AuthHeaderSourceAuto)
	require.Error(t, err)
	assert.Equal(t, "is forbidden", err.Error())
	require.Empty(t, headers)
}

func Test_buildEngine_TestEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newTestFileAdapterConfig(t, "rbac_model.conf", "", "")
	engine, closers, err := buildEngine(newRegistry(), cfg)
	require.NoError(t, err)
	defer closers.Close()

	t.Run("healthz OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("readyz OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("metrics OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("auth without forwarded headers Forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("unknown route returns NotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/anything", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
	})
}

func Test_buildEngine_JWTNoneMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	jwtCfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     "none", // no keys in jwks
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
		UseX509:     false,
	}

	cfg := newTestFileAdapterConfig(t, "rbac_model.conf", "", "")
	cfg.Auth.JWTConfig = jwtCfg

	engine, closers, err := buildEngine(newRegistry(), cfg)
	require.NoError(t, err)
	defer closers.Close()

	t.Run("no Bearer token -> returns 401 Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set(HeaderForwardedMethod, http.MethodGet)
		req.Header.Set(HeaderForwardedHost, "svc.local")
		req.Header.Set(HeaderForwardedURI, "/some/resource")
		req.Header.Set(HeaderForwardedProto, "http")
		req.Header.Set(HeaderForwardedFor, "1.2.3.4")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, `Bearer realm="https://issuer.example.internal", error="invalid_token"`, w.Result().Header.Get(HeaderWWWAuthenticate))
	})

	t.Run("with invalid Bearer token -> returns 401 Unauthorized", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))
		token := fmt.Sprintf("%s.%s.", header, payload) // no signature

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set(HeaderForwardedMethod, http.MethodGet)
		req.Header.Set(HeaderForwardedHost, "svc.local")
		req.Header.Set(HeaderForwardedURI, "/some/resource")
		req.Header.Set(HeaderForwardedProto, "http")
		req.Header.Set(HeaderForwardedFor, "1.2.3.4")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, `Bearer realm="https://issuer.example.internal", error="invalid_token"`, w.Result().Header.Get(HeaderWWWAuthenticate))
	})
}

//nolint:canonicalheader
func Test_getForwardedTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("forward-auth: happy path", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set(HeaderForwardedMethod, http.MethodPost)
		req.Header.Set(HeaderForwardedHost, "svc.local")
		req.Header.Set(HeaderForwardedURI, "/target/path?q=1")
		c.Request = req

		method, host, uri, err := getForwardedTarget(c, config.AuthHeaderSourceForwarded)
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, method)
		assert.Equal(t, "svc.local", host)
		assert.Equal(t, "/target/path?q=1", uri)
	})

	t.Run("forward-auth: missing headers -> error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// no forwarded headers
		c.Request = httptest.NewRequest(http.MethodGet, "/v1/auth", nil)

		_, _, _, err := getForwardedTarget(c, config.AuthHeaderSourceAuto)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingForwardAuthHeaders)
	})

	t.Run("nginx auth_request: happy path", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set("X-Original-Method", http.MethodGet)
		req.Header.Set("X-Original-URI", "/get?x=1")
		req.Header.Set("X-Original-URL", "http://echo.127.0.0.1.nip.io:30180/get?x=1")
		c.Request = req

		method, host, uri, err := getForwardedTarget(c, config.AuthHeaderSourceOriginal)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, method)
		assert.Equal(t, "echo.127.0.0.1.nip.io:30180", host)
		assert.Equal(t, "/get?x=1", uri)
	})

	t.Run("nginx auth_request: URI fallback from URL when X-Original-URI is empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set("X-Original-Method", http.MethodGet)
		// no X-Original-URI on purpose
		req.Header.Set("X-Original-URL", "http://echo.127.0.0.1.nip.io:30180/some/path?q=42")
		c.Request = req

		method, host, uri, err := getForwardedTarget(c, config.AuthHeaderSourceOriginal)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, method)
		assert.Equal(t, "echo.127.0.0.1.nip.io:30180", host)
		// should be taken from the parsed URL
		assert.Equal(t, "/some/path?q=42", uri)
	})

	t.Run("nginx auth_request: bad X-Original-URL -> error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set("X-Original-Method", http.MethodGet)
		req.Header.Set("X-Original-URI", "/get")
		req.Header.Set("X-Original-URL", "http://%/bad") // force parse error
		c.Request = req

		_, _, _, err := getForwardedTarget(c, config.AuthHeaderSourceAuto)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid X-Original-URL")
	})

	t.Run("nginx auth_request: missing host because no X-Original-URL -> error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
		req.Header.Set("X-Original-Method", http.MethodGet)
		req.Header.Set("X-Original-URI", "/get")
		c.Request = req

		_, _, _, err := getForwardedTarget(c, config.AuthHeaderSourceAuto)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingForwardAuthHeaders)
	})
}
