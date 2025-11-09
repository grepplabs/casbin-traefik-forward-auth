package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
	tlsconfig "github.com/grepplabs/cert-source/config"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWKSet_JWKSURLNone_ReturnsEmptySet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     "none",
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
	}

	set, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, set)
	require.Equal(t, 0, set.Len())
}

func TestNewJWKSet(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.JWTConfig
	}{
		{
			name: "LoadsFromGoogle",
			cfg: config.JWTConfig{
				Enabled:     true,
				JWKSURL:     "https://www.googleapis.com/oauth2/v3/certs",
				InitTimeout: 10 * time.Second,
				Issuer:      "https://accounts.google.com",
				Audience:    "test-audience",
			},
		},
		{
			name: "LoadsFromGoogleTLS",
			cfg: config.JWTConfig{
				Enabled:     true,
				JWKSURL:     "https://www.googleapis.com/oauth2/v3/certs",
				InitTimeout: 10 * time.Second,
				Issuer:      "https://accounts.google.com",
				Audience:    "test-audience",
				TLS: tlsconfig.TLSClientConfig{
					Enable:             true,
					InsecureSkipVerify: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			loadedSet, err := newJWKSet(ctx, tt.cfg)
			if err != nil {
				t.Skipf("skipping: could not load JWKS from remote source: %v", err)
			}

			require.NotNil(t, loadedSet, "expected non-nil JWK set")
			require.Positive(t, loadedSet.Len(), "expected JWK set length > 0")

			firstKey, ok := loadedSet.Key(0)
			require.True(t, ok, "expected to retrieve first key")

			kid, ok := firstKey.KeyID()
			require.True(t, ok, "expected key to have key ID")
			assert.NotEmpty(t, kid, "expected non-empty key ID")
		})
	}
}

func TestNewJWKSet_LoadsFromHTTPServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	publicPath := filepath.Join(tmpDir, "public.jwks.json")

	_, origSet, err := generateJWKS("", publicPath)
	require.NoError(t, err)
	require.Equal(t, 1, origSet.Len())

	jwksBytes, err := os.ReadFile(publicPath)
	require.NoError(t, err)

	const certsPath = "/realms/master/protocol/openid-connect/certs"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != certsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer server.Close()

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     server.URL + certsPath,
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
	}

	loadedSet, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, loadedSet)
	require.Equal(t, 1, loadedSet.Len())

	origKey, ok := origSet.Key(0)
	require.True(t, ok)
	loadedKey, ok := loadedSet.Key(0)
	require.True(t, ok)

	origKID, ok := origKey.KeyID()
	require.True(t, ok)
	loadedKID, ok := loadedKey.KeyID()
	require.True(t, ok)
	assert.Equal(t, origKID, loadedKID)
}

func TestNewJWKSet_LoadsFromHTTPServerTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	publicPath := filepath.Join(tmpDir, "public.jwks.json")

	_, origSet, err := generateJWKS("", publicPath)
	require.NoError(t, err)
	require.Equal(t, 1, origSet.Len())

	jwksBytes, err := os.ReadFile(publicPath)
	require.NoError(t, err)

	const certsPath = "/realms/master/protocol/openid-connect/certs"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != certsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer server.Close()

	rootCA := storeTLSServerCertPEM(t, server)

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     server.URL + certsPath,
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
		TLS: tlsconfig.TLSClientConfig{
			Enable: true,
			File: tlsconfig.TLSClientFiles{
				RootCAs: rootCA,
			},
		},
	}
	loadedSet, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, loadedSet)
	require.Equal(t, 1, loadedSet.Len())

	origKey, ok := origSet.Key(0)
	require.True(t, ok)
	loadedKey, ok := loadedSet.Key(0)
	require.True(t, ok)

	origKID, ok := origKey.KeyID()
	require.True(t, ok)
	loadedKID, ok := loadedKey.KeyID()
	require.True(t, ok)
	assert.Equal(t, origKID, loadedKID)
}

func storeTLSServerCertPEM(t *testing.T, server *httptest.Server) string {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server-cert.pem")

	cert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write server certificate to %s: %v", certPath, err)
	}
	return certPath
}

func TestNewJWKSet_LoadsFromFileURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	publicPath := filepath.Join(tmpDir, "public.jwks.json")

	_, origSet, err := generateJWKS("", publicPath)
	require.NoError(t, err)
	require.Equal(t, 1, origSet.Len())

	loadedPubSet, err := jwk.ReadFile(publicPath)
	require.NoError(t, err)
	require.Equal(t, 1, loadedPubSet.Len())

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     "file://" + publicPath,
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
	}

	loadedSet, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, loadedSet)
	require.Equal(t, 1, loadedSet.Len())

	origKey, ok := origSet.Key(0)
	require.True(t, ok)
	loadedKey, ok := loadedSet.Key(0)
	require.True(t, ok)

	origKID, ok := origKey.KeyID()
	require.True(t, ok, "original key should have kid")
	loadedKID, ok := loadedKey.KeyID()
	require.True(t, ok, "loaded key should have kid")
	assert.Equal(t, origKID, loadedKID, "kid of loaded key should match original")
}

func TestNewJWKSet_LoadsFromX509FileURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "example-cert.pem")
	keyPath := filepath.Join(tmpDir, "example-key.pem")

	_, privKey, err := generateSelfSignedCert(certPath, keyPath)
	require.NoError(t, err)

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     "file://" + certPath,
		InitTimeout: 10 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
		UseX509:     true,
	}

	pubSetLoaded, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pubSetLoaded)
	require.Equal(t, 1, pubSetLoaded.Len())

	jwkKey, err := jwk.Import(privKey)
	require.NoError(t, err)

	privJWK, ok := jwkKey.(jwk.RSAPrivateKey)
	require.True(t, ok)

	err = privJWK.Set(jwk.AlgorithmKey, "RS256")
	require.NoError(t, err)
}

func TestIsFileSet(t *testing.T) {
	type tc struct {
		name   string
		url    string
		expect bool
	}
	cases := []tc{
		{
			name:   "local file path (no scheme) -> true",
			url:    "/etc/jwks.json",
			expect: true,
		},
		{
			name:   "relative path -> true",
			url:    "keys/jwks.json",
			expect: true,
		},
		{
			name:   "http URL -> false",
			url:    "http://auth.example.com/jwks.json",
			expect: false,
		},
		{
			name:   "https URL -> false",
			url:    "https://auth.example.com/jwks.json",
			expect: false,
		},
		{
			name:   "empty string -> true (not http/https)",
			url:    "",
			expect: true,
		},
		{
			name:   "non-http scheme (file://) -> true",
			url:    "file:///etc/jwks.json",
			expect: true,
		},
		{
			name:   "non-http scheme (s3://) -> true",
			url:    "s3://bucket/jwks.json",
			expect: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.JWTConfig{
				JWKSURL: c.url,
			}
			got := isFileSet(cfg)
			require.Equal(t, c.expect, got, "unexpected result for %q", c.url)
		})
	}
}

// nolint: nonamedreturns
func generateJWKS(privateJWKSPath, publicJWKSPath string) (privSet jwk.Set, pubSet jwk.Set, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}
	privAny, err := jwk.Import(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("import private key: %w", err)
	}
	privJWK, ok := privAny.(jwk.RSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not a JWK")
	}
	pubAny, err := jwk.PublicKeyOf(privJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("public key of private jwk: %w", err)
	}
	pubJWK, ok := pubAny.(jwk.RSAPublicKey)
	if !ok {
		return nil, nil, errors.New("public key is not a JWK")
	}
	kid := fmt.Sprintf("rsa-%d", time.Now().Unix())

	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}
	if err := privJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, nil, err
	}
	if err := privJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, nil, err
	}

	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, nil, err
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, nil, err
	}

	privSet = jwk.NewSet()
	if err := privSet.AddKey(privJWK); err != nil {
		return nil, nil, err
	}

	pubSet = jwk.NewSet()
	if err := pubSet.AddKey(pubJWK); err != nil {
		return nil, nil, err
	}

	if privateJWKSPath != "" {
		if err := writeJWKSFile(privateJWKSPath, privSet); err != nil {
			return nil, nil, fmt.Errorf("write private jwks: %w", err)
		}
	}
	if publicJWKSPath != "" {
		if err := writeJWKSFile(publicJWKSPath, pubSet); err != nil {
			return nil, nil, fmt.Errorf("write public jwks: %w", err)
		}
	}
	return privSet, pubSet, nil
}

func writeJWKSFile(path string, set jwk.Set) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(set)
}

func generateSelfSignedCert(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "example.local",
			Organization: []string{"Example Corp"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, fmt.Errorf("encode cert pem: %w", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()

	privDER := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}); err != nil {
		return nil, nil, fmt.Errorf("encode key pem: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, priv, nil
}
