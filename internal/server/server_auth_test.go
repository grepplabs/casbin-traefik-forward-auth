// nolint: funlen
package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAuth_RBAC_PubSub(t *testing.T) {
	routes := mustReadFile(t, filepath.Join("testdata", "pubsub-routes.yaml"))

	policies := `
p, iam::123456789012:sa/9e4fdb1c-3345-4c07-98d9-73b993c9dd42, pubsub:eu-central-1:123456789012:topics/orders, pubsub:publish
p, iam::123456789012:sa/9e4fdb1c-3345-4c07-98d9-73b993c9dd42, pubsub:eu-central-1:123456789012:topics/orders/subscriptions/order-updates, pubsub:read
`

	gin.SetMode(gin.TestMode)
	cfg := newTestFileAdapterConfig(t, "rbac_model.conf", policies, routes)
	engine, closers, err := buildEngine(newRegistry(), cfg)
	require.NoError(t, err)
	defer closers.Close()

	urls := []string{
		"/v1alpha/publish",
		"/v1alpha/subscriptions/order-updates/pull",
		"/v1alpha/subscriptions/order-updates/ack",
		"/v1alpha/subscriptions/order-updates/nack",
	}

	type scenario struct {
		name     string
		host     string
		tokenOpt []tokenOption
		wantCode int
	}

	scenarios := []scenario{
		{
			name:     "orders topic OK",
			host:     "orders.example.com",
			wantCode: http.StatusOK,
		},
		{
			name:     "missing token forbidden",
			host:     "orders.example.com",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "different project forbidden",
			host:     "orders.example.com",
			tokenOpt: []tokenOption{withClaim("acme/project/project.id", "4711")},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "different subject forbidden",
			host:     "orders.example.com",
			tokenOpt: []tokenOption{withClaim("sub", "b3d65073-9fdd-45b3-ad71-74da3c831f77")},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "wrong topic forbidden",
			host:     "notification.example.com",
			tokenOpt: nil,
			wantCode: http.StatusForbidden,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			for _, u := range urls {
				t.Run(u, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
					req.Header.Set(HeaderForwardedURI, u)
					req.Header.Set(HeaderForwardedMethod, http.MethodPost)
					req.Header.Set(HeaderForwardedHost, sc.host)
					req.Host = "casbin-auth.acme.cloud"

					if sc.name != "missing token forbidden" {
						req.Header.Set("Authorization", "Bearer "+newTestBearerToken(t, sc.tokenOpt...))
					}

					w := httptest.NewRecorder()
					engine.ServeHTTP(w, req)

					require.Equalf(t, sc.wantCode, w.Code, "url=%s body=%s", u, w.Body.String())
				})
			}
		})
	}
}

func TestAuth_RBAC_PubSub_NoPolicies_Forbidden(t *testing.T) {
	routes := mustReadFile(t, filepath.Join("testdata", "pubsub-routes.yaml"))

	gin.SetMode(gin.TestMode)
	cfg := newTestFileAdapterConfig(t, "rbac_model.conf", "", routes)
	engine, closers, err := buildEngine(newRegistry(), cfg)
	require.NoError(t, err)
	defer closers.Close()

	urls := []string{
		"/v1alpha/publish",
		"/v1alpha/subscriptions/order-updates/pull",
		"/v1alpha/subscriptions/order-updates/ack",
		"/v1alpha/subscriptions/order-updates/nack",
	}

	for _, u := range urls {
		t.Run(fmt.Sprintf("orders topic - authorize %s OK", u), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
			req.Header.Set("Authorization", "Bearer "+newTestBearerToken(t))
			req.Header.Set(HeaderForwardedURI, u)
			req.Header.Set(HeaderForwardedMethod, http.MethodPost)
			req.Header.Set(HeaderForwardedHost, "orders.example.com")
			req.Host = "casbin-auth.acme.cloud"

			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equalf(t, http.StatusForbidden, w.Code, "url %s body %s", u, w.Body.String())
		})
	}
}

func TestAuth_KeyMatch(t *testing.T) {
	routes := mustReadFile(t, filepath.Join("testdata", "keymatch-routes.yaml"))

	policies := `
p, alice, /alice_data/*, GET
p, alice, /alice_data/resource1, POST

p, bob, /alice_data/resource2, GET
p, bob, /bob_data/*, POST

p, cathy, /cathy_data, (GET)|(POST)
`

	gin.SetMode(gin.TestMode)
	cfg := newTestFileAdapterConfig(t, "keymatch_model.conf", policies, routes)
	engine, closers, err := buildEngine(newRegistry(), cfg)
	require.NoError(t, err)
	defer closers.Close()

	type tc struct {
		name     string
		user     string
		url      string
		method   string
		wantCode int
	}

	tests := []tc{
		// alice
		{name: "alice GET any under /alice_data/*", user: "alice", url: "/alice_data/foo", method: http.MethodGet, wantCode: http.StatusOK},
		{name: "alice POST /alice_data/resource1 allowed", user: "alice", url: "/alice_data/resource1", method: http.MethodPost, wantCode: http.StatusOK},
		{name: "alice GET /alice_data/resource2 allowed via wildcard", user: "alice", url: "/alice_data/resource2", method: http.MethodGet, wantCode: http.StatusOK},
		{name: "alice POST /bob_data denied", user: "alice", url: "/bob_data/logs", method: http.MethodPost, wantCode: http.StatusForbidden},

		// bob
		{name: "bob GET /alice_data/resource2 allowed", user: "bob", url: "/alice_data/resource2", method: http.MethodGet, wantCode: http.StatusOK},
		{name: "bob POST /bob_data/* allowed", user: "bob", url: "/bob_data/anything", method: http.MethodPost, wantCode: http.StatusOK},
		{name: "bob GET /bob_data/* denied (only POST)", user: "bob", url: "/bob_data/anything", method: http.MethodGet, wantCode: http.StatusForbidden},
		{name: "bob POST /alice_data/resource1 denied", user: "bob", url: "/alice_data/resource1", method: http.MethodPost, wantCode: http.StatusForbidden},

		// cathy
		{name: "cathy GET /cathy_data allowed", user: "cathy", url: "/cathy_data", method: http.MethodGet, wantCode: http.StatusOK},
		{name: "cathy POST /cathy_data allowed", user: "cathy", url: "/cathy_data", method: http.MethodPost, wantCode: http.StatusOK},
		{name: "cathy GET /cathy_data/extra denied (exact match only)", user: "cathy", url: "/cathy_data/extra", method: http.MethodGet, wantCode: http.StatusForbidden},

		// unknown / edge cases
		{name: "unknown user denied", user: "unknown", url: "/alice_data/foo", method: http.MethodGet, wantCode: http.StatusForbidden},
		{name: "unsupported verb denied", user: "alice", url: "/alice_data/foo", method: http.MethodPut, wantCode: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The handler reads forwarded headers; the request method to /v1/auth can stay GET.
			req := httptest.NewRequest(http.MethodGet, "/v1/auth", nil)
			req.Header.Set("Authorization", "Basic "+newTestBasic(t, tt.user))
			req.Header.Set(HeaderForwardedURI, tt.url)
			req.Header.Set(HeaderForwardedMethod, tt.method)
			req.Header.Set(HeaderForwardedHost, "example.com")
			req.Host = "forward-auth.acme.cloud"

			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equalf(t, tt.wantCode, w.Code, "url %s method %s body %s", tt.url, tt.method, w.Body.String())
		})
	}
}

func newTestFileAdapterConfig(t *testing.T, model string, policies string, routes string) config.Config {
	t.Helper()

	td := t.TempDir()
	policyPath := filepath.Join(td, "policy.csv")
	require.NoError(t, os.WriteFile(policyPath, []byte(policies), fileModeUserRW))

	routesPath := filepath.Join(td, "routes.yaml")
	require.NoError(t, os.WriteFile(routesPath, []byte(routes), fileModeUserRW))

	return config.Config{
		Server: config.ServerConfig{
			Addr: "127.0.0.1:0",
		},
		Auth: config.AuthConfig{
			RouteConfigPath: routesPath,
		},
		Casbin: config.CasbinConfig{
			Model:   model,
			Adapter: config.AdapterFile,
			AdapterFile: config.CasbinAdapterFileConfig{
				PolicyPath: policyPath,
			},
		},
	}
}

type tokenOption func(claims jwt.MapClaims)

func withClaim(key string, value any) tokenOption {
	return func(c jwt.MapClaims) {
		c[key] = value
	}
}

func newTestBearerToken(t *testing.T, opts ...tokenOption) string {
	t.Helper()

	claims := jwt.MapClaims{
		"acme/project/project.id": "123456789012",
		"aud":                     []string{"acme", "api"},
		"azp":                     "michal-test-aoeyd81@sa.acme.cloud",
		"email":                   "michal-test-aoeyd81@sa.acme.cloud",
		"exp":                     1760033573,
		"iat":                     1760029973,
		"iss":                     "acme/serviceaccount",
		"jti":                     "a03923c1-5e99-488a-bd1a-e201af956d17",
		"sub":                     "9e4fdb1c-3345-4c07-98d9-73b993c9dd42",
	}
	for _, opt := range opts {
		opt(claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	return token
}

func newTestBasic(t *testing.T, username string) string {
	t.Helper()
	auth := fmt.Sprintf("%s:%s", username, "pass")
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
