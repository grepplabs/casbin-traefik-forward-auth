package e2e

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	httphelper "github.com/gruntwork-io/terratest/modules/http-helper"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/retry"
	terratesting "github.com/gruntwork-io/terratest/modules/testing"
	"github.com/stretchr/testify/require"
)

const (
	configPath = "../../kubeconfig-casbin-traefik"
)

func newKubectlOptions() *k8s.KubectlOptions {
	return k8s.NewKubectlOptions("", configPath, "")
}

func kubectlDeleteIgnoreNotFound(t terratesting.TestingT, options *k8s.KubectlOptions, configPath string) {
	require.NoError(t, k8s.RunKubectlE(t, options, "delete", "--ignore-not-found=true", "-f", configPath))
}

func buildURL(baseUrl, path string) string {
	return baseUrl + path
}

func requireRejected(t *testing.T, method string, url string, headers map[string]string) {
	HTTPDoWithCustomValidationRetry(t, method, url, headers,
		func(status int, body string) bool {
			if status != http.StatusForbidden {
				return false
			}
			if body == `{"error":"rejected"}` {
				return true
			}
			if strings.Contains(strings.ToLower(body), "nginx") {
				return true
			}
			return false
		}, 10, 2*time.Second,
	)
}

func requireNotFound(t *testing.T, method string, url string, headers map[string]string) {
	HTTPDoWithCustomValidationRetry(t, method, url, headers,
		func(status int, body string) bool {
			if status != http.StatusForbidden {
				return false
			}
			if body == `{"error":"404 page not found"}` {
				return true
			}
			if strings.Contains(strings.ToLower(body), "nginx") {
				return true
			}
			return false
		}, 10, 2*time.Second,
	)
}

func requireOK(t *testing.T, method string, url string, headers map[string]string) {
	httphelper.HTTPDoWithRetry(t, method, url, nil, headers, http.StatusOK, 5, 2*time.Second, nil)
}

func newTestBearerToken(t *testing.T) string {
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

func HTTPDoWithCustomValidationRetry(t *testing.T, method string, url string, headers map[string]string, validateResponse func(int, string) bool, retries int, sleepBetweenRetries time.Duration) {
	t.Helper()
	_, err := retry.DoWithRetryE(
		t,
		fmt.Sprintf("HTTP %s to URL %s", method, url),
		retries,
		sleepBetweenRetries,
		func() (string, error) {
			httphelper.HTTPDoWithCustomValidation(t, method, url, nil, headers, validateResponse, nil)
			return "ok", nil
		},
	)
	if err != nil {
		t.Fatalf("HTTP request failed after %d retries: %v", retries, err)
	}
}
