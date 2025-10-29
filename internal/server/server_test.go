package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
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

	_, err := forwardAuth(c, authEngine)
	require.Error(t, err)
	assert.Equal(t, "missing auth headers", err.Error())
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

	body, err := forwardAuth(c, authEngine)
	require.NoError(t, err)
	assert.Equal(t, "allowed", body)

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

	_, err := forwardAuth(c, authEngine)
	require.Error(t, err)
	assert.Equal(t, "is forbidden", err.Error())
}

func Test_buildEngine_TestEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newTestFileAdapterConfig(t, "rbac_model.conf", "", "")
	engine, closers, err := buildEngine(cfg)
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
