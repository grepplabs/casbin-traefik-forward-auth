package jwt

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
)

func verifyToken(signedJWT string, cfg *config.JWTConfig, pubSet jwk.Set) (jwt.Token, error) {
	if isFileSet(cfg) && cfg.UseX509 {
		return verifyX509Token(signedJWT, cfg, pubSet)
	} else {
		return verifyJWKToken(signedJWT, cfg, pubSet)
	}
}

func verifyJWKToken(signedJWT string, cfg *config.JWTConfig, pubSet jwk.Set) (jwt.Token, error) {
	if pubSet == nil || pubSet.Len() == 0 {
		return nil, errors.New("no keys in public JWKS")
	}
	token, err := jwt.Parse(
		[]byte(signedJWT),
		jwt.WithKeySet(pubSet),         // verify signature using the JWKS
		jwt.WithVerify(true),           // actually verify sig
		jwt.WithValidate(true),         // validate std claims (exp, nbf, etc.)
		jwt.WithIssuer(cfg.Issuer),     // require matching iss
		jwt.WithAudience(cfg.Audience), // require matching aud
	)
	if err != nil {
		return nil, fmt.Errorf("verify JWK token: %w", err)
	}
	return token, nil
}

func verifyX509Token(signedJWT string, cfg *config.JWTConfig, pubSet jwk.Set) (jwt.Token, error) {
	if pubSet == nil || pubSet.Len() == 0 {
		return nil, errors.New("no keys in public JWKS")
	}
	msg, err := jws.Verify([]byte(signedJWT), jws.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true), jws.WithRequireKid(false)))
	if err != nil {
		return nil, fmt.Errorf("verify x509 token: %w", err)
	}
	token, err := jwt.Parse(msg,
		jwt.WithVerify(false),          // don't re-check signature
		jwt.WithValidate(true),         // validate std claims (exp, nbf, etc.)
		jwt.WithIssuer(cfg.Issuer),     // require matching iss
		jwt.WithAudience(cfg.Audience), // require matching aud
	)
	if err != nil {
		return nil, fmt.Errorf("validate x509 token: %w", err)
	}
	return token, nil
}
