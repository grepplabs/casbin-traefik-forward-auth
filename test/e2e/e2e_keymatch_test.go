package e2e

import (
	"net/http"
	"testing"
	"time"

	httphelper "github.com/gruntwork-io/terratest/modules/http-helper"
	"github.com/gruntwork-io/terratest/modules/k8s"
)

func Test_KeyMatch(t *testing.T) {
	options := newKubectlOptions()
	k8s.KubectlApplyFromKustomize(t, options, "testmanifests/")

	kubeResourcePath := "testdata/keymatch-echo-policy.yaml"
	defer kubectlDeleteIgnoreNotFound(t, options, kubeResourcePath)
	k8s.KubectlApply(t, options, kubeResourcePath)

	type target struct {
		name    string
		baseURL string
	}
	targets := []target{
		{name: "traefik", baseURL: "http://keymatch.127.0.0.1.nip.io:30080"},
		{name: "nginx", baseURL: "http://keymatch.127.0.0.1.nip.io:30180"},
	}

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

		// unknown / edge
		{name: "unknown user denied", user: "unknown", url: "/alice_data/foo", method: http.MethodGet, wantCode: http.StatusForbidden},
		{name: "unsupported verb denied", user: "alice", url: "/alice_data/foo", method: http.MethodPut, wantCode: http.StatusForbidden},
	}

	for _, tg := range targets {
		t.Run("target="+tg.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					headers := map[string]string{
						"Authorization": "Basic " + newTestBasic(t, tt.user),
					}
					fullURL := buildURL(tg.baseURL, tt.url)
					switch tt.wantCode {
					case http.StatusOK:
						requireOK(t, tt.method, fullURL, headers)
					case http.StatusForbidden:
						requireRejected(t, tt.method, fullURL, headers)
					default:
						_ = httphelper.HTTPDoWithRetry(t, tt.method, fullURL, nil, headers, tt.wantCode, 10, 2*time.Second, nil)
					}
				})
			}
		})
	}
	k8s.KubectlDelete(t, options, kubeResourcePath)
	for _, tg := range targets {
		headers := map[string]string{
			"Authorization": "Basic " + newTestBasic(t, "alice"),
		}
		requireRejected(t, http.MethodGet, buildURL(tg.baseURL, "/alice_data/foo"), headers)
	}
}
