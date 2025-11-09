package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestVerifyToken_UsesX509Path(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	_, privKey, err := generateSelfSignedCert(certPath, keyPath)
	require.NoError(t, err)

	cfg := config.JWTConfig{
		Enabled:     true,
		JWKSURL:     "file://" + certPath,
		InitTimeout: 5 * time.Second,
		Issuer:      "https://issuer.example.internal",
		Audience:    "my-audience",
		UseX509:     true,
	}

	pubSet, err := newJWKSet(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pubSet)
	require.Equal(t, 1, pubSet.Len())

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	err = privJWK.Set(jwk.AlgorithmKey, "RS256")
	require.NoError(t, err)

	signedJWT, err := signToken("alice", privJWK, cfg)
	require.NoError(t, err)

	token, err := verifyToken(signedJWT, &cfg, pubSet)
	require.NoError(t, err)
	require.NotNil(t, token)
}

func TestVerifyToken_UsesJWKPath(t *testing.T) {
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

	privKey, ok := privSet.Key(0)
	require.True(t, ok)

	signedJWT, err := signToken("alice", privKey, cfg)
	require.NoError(t, err)

	token, err := verifyToken(signedJWT, &cfg, pubSet)
	require.NoError(t, err)
	require.NotNil(t, token)
}

func TestVerifyJWKToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "my-audience",
		}

		// generate a matching private/public pair
		tmpDir := t.TempDir()
		pubPath := filepath.Join(tmpDir, "pub.jwks.json")

		privSet, pubSet, err := generateJWKS("", pubPath)
		require.NoError(t, err)
		require.Equal(t, 1, privSet.Len())
		require.Equal(t, 1, pubSet.Len())

		privKey, ok := privSet.Key(0)
		require.True(t, ok)

		signedJWT, err := signToken("alice", privKey, cfg)
		require.NoError(t, err)

		token, err := verifyJWKToken(signedJWT, &cfg, pubSet)
		require.NoError(t, err)
		require.NotNil(t, token)
	})

	t.Run("wrong issuer -> error", func(t *testing.T) {
		// config we VERIFY with
		verifyCfg := config.JWTConfig{
			Issuer:   "https://right-issuer.example.internal",
			Audience: "my-audience",
		}

		// generate JWKS and sign using a DIFFERENT issuer
		tmpDir := t.TempDir()
		pubPath := filepath.Join(tmpDir, "pub.jwks.json")

		privSet, pubSet, err := generateJWKS("", pubPath)
		require.NoError(t, err)

		privKey, ok := privSet.Key(0)
		require.True(t, ok)

		signCfg := config.JWTConfig{
			Issuer:   "https://wrong-issuer.example.internal",
			Audience: "my-audience",
		}

		signedJWT, err := signToken("alice", privKey, signCfg)
		require.NoError(t, err)

		token, err := verifyJWKToken(signedJWT, &verifyCfg, pubSet)
		require.Error(t, err)
		require.Nil(t, token)
	})

	t.Run("wrong audience -> error", func(t *testing.T) {
		verifyCfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "expected-audience",
		}

		tmpDir := t.TempDir()
		pubPath := filepath.Join(tmpDir, "pub.jwks.json")

		privSet, pubSet, err := generateJWKS("", pubPath)
		require.NoError(t, err)

		privKey, ok := privSet.Key(0)
		require.True(t, ok)

		signCfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "other-audience",
		}

		signedJWT, err := signToken("alice", privKey, signCfg)
		require.NoError(t, err)

		token, err := verifyJWKToken(signedJWT, &verifyCfg, pubSet)
		require.Error(t, err)
		require.Nil(t, token)
	})

	t.Run("expired -> error", func(t *testing.T) {
		cfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "my-audience",
		}

		tmpDir := t.TempDir()
		pubPath := filepath.Join(tmpDir, "pub.jwks.json")

		privSet, pubSet, err := generateJWKS("", pubPath)
		require.NoError(t, err)
		require.Equal(t, 1, privSet.Len())
		require.Equal(t, 1, pubSet.Len())

		privKey, ok := privSet.Key(0)
		require.True(t, ok)

		expiredTok, err := jwt.NewBuilder().
			Issuer(cfg.Issuer).
			Audience([]string{cfg.Audience}).
			Subject("alice").
			Expiration(time.Now().Add(-1 * time.Hour)).
			IssuedAt(time.Now().Add(-2 * time.Hour)).
			Build()
		require.NoError(t, err)

		signedExpiredBytes, err := jwt.Sign(expiredTok, jwt.WithKey(jwa.RS256(), privKey))
		require.NoError(t, err)

		token, err := verifyJWKToken(string(signedExpiredBytes), &cfg, pubSet)
		require.Error(t, err)
		require.Nil(t, token)
	})

	t.Run("no keys -> error", func(t *testing.T) {
		cfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "my-audience",
		}

		emptySet := jwk.NewSet()

		token, err := verifyJWKToken("whatever", &cfg, emptySet)
		require.Error(t, err)
		require.Nil(t, token)
	})
}

func TestVerifyX509Token(t *testing.T) {
	// nolint:nonamedreturns
	makePubSet := func(t *testing.T, issuer, audience string) (cfg config.JWTConfig, pubSet jwk.Set, privKey *rsa.PrivateKey) {
		t.Helper()

		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")
		keyPath := filepath.Join(tmpDir, "key.pem")

		_, priv, err := generateSelfSignedCert(certPath, keyPath)
		require.NoError(t, err)

		cfg = config.JWTConfig{
			Enabled:     true,
			JWKSURL:     "file://" + certPath,
			InitTimeout: 5 * time.Second,
			Issuer:      issuer,
			Audience:    audience,
			UseX509:     true,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		pubSetLoaded, err := newJWKSet(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, pubSetLoaded)
		require.Positive(t, pubSetLoaded.Len())

		return cfg, pubSetLoaded, priv
	}

	t.Run("ok", func(t *testing.T) {
		cfg, pubSet, rsaPriv := makePubSet(t,
			"https://issuer.example.internal",
			"my-audience",
		)

		tok, err := jwt.NewBuilder().
			Issuer(cfg.Issuer).
			Audience([]string{cfg.Audience}).
			Subject("alice").
			Expiration(time.Now().Add(1 * time.Hour)).
			IssuedAt(time.Now()).
			Build()
		require.NoError(t, err)

		signedBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaPriv))
		require.NoError(t, err)

		parsed, err := verifyX509Token(string(signedBytes), &cfg, pubSet)
		require.NoError(t, err)
		require.NotNil(t, parsed)
	})

	t.Run("wrong issuer -> error", func(t *testing.T) {
		verifyCfg, pubSet, rsaPriv := makePubSet(t,
			"https://right-issuer.example.internal",
			"my-audience",
		)

		signIssuer := "https://wrong-issuer.example.internal"

		tok, err := jwt.NewBuilder().
			Issuer(signIssuer).
			Audience([]string{verifyCfg.Audience}).
			Subject("alice").
			Expiration(time.Now().Add(1 * time.Hour)).
			IssuedAt(time.Now()).
			Build()
		require.NoError(t, err)

		signedBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaPriv))
		require.NoError(t, err)

		parsed, err := verifyX509Token(string(signedBytes), &verifyCfg, pubSet)
		require.Error(t, err)
		require.Nil(t, parsed)
	})

	t.Run("wrong audience -> error", func(t *testing.T) {
		verifyCfg, pubSet, rsaPriv := makePubSet(t,
			"https://issuer.example.internal",
			"expected-audience",
		)

		signAudience := "other-audience"

		tok, err := jwt.NewBuilder().
			Issuer(verifyCfg.Issuer).
			Audience([]string{signAudience}).
			Subject("alice").
			Expiration(time.Now().Add(1 * time.Hour)).
			IssuedAt(time.Now()).
			Build()
		require.NoError(t, err)

		signedBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaPriv))
		require.NoError(t, err)

		parsed, err := verifyX509Token(string(signedBytes), &verifyCfg, pubSet)
		require.Error(t, err)
		require.Nil(t, parsed)
	})

	t.Run("expired -> error", func(t *testing.T) {
		cfg, pubSet, rsaPriv := makePubSet(t,
			"https://issuer.example.internal",
			"my-audience",
		)

		tok, err := jwt.NewBuilder().
			Issuer(cfg.Issuer).
			Audience([]string{cfg.Audience}).
			Subject("alice").
			Expiration(time.Now().Add(-1 * time.Hour)). // already expired
			IssuedAt(time.Now().Add(-2 * time.Hour)).
			Build()
		require.NoError(t, err)

		signedBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), rsaPriv))
		require.NoError(t, err)

		parsed, err := verifyX509Token(string(signedBytes), &cfg, pubSet)
		require.Error(t, err)
		require.Nil(t, parsed)
	})

	t.Run("no keys -> error", func(t *testing.T) {
		cfg := config.JWTConfig{
			Issuer:   "https://issuer.example.internal",
			Audience: "my-audience",
			UseX509:  true,
		}

		emptySet := jwk.NewSet()

		parsed, err := verifyX509Token("whatever", &cfg, emptySet)
		require.Error(t, err)
		require.Nil(t, parsed)
	})
}

func signToken(subject string, signingKey jwk.Key, config config.JWTConfig) (string, error) {
	alg, ok := signingKey.Algorithm()
	if !ok {
		return "", errors.New("jwk does not have a algorithm with private material")
	}
	now := time.Now().UTC()
	tok, err := jwt.NewBuilder().
		Subject(subject).
		Issuer(config.Issuer).
		Audience([]string{config.Audience}).
		IssuedAt(now).
		Expiration(now.Add(15 * time.Minute)). // adjust if you want longer-lived tokens
		Build()
	if err != nil {
		return "", fmt.Errorf("build jwt: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, signingKey))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(signed), nil
}
