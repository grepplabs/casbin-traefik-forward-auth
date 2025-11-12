package e2e

import (
	"net/http"
	"testing"

	"github.com/gruntwork-io/terratest/modules/k8s"
)

func Test_RBAC_PubSub(t *testing.T) {
	options := newKubectlOptions()
	k8s.KubectlApplyFromKustomize(t, options, "testmanifests/")

	type target struct {
		name    string
		baseURL string
	}
	targets := []target{
		{name: "traefik", baseURL: "http://rbac.127.0.0.1.nip.io:30080"},
		{name: "nginx", baseURL: "http://rbac.127.0.0.1.nip.io:30180"},
	}

	kubeResourcePath := "testdata/rbac-echo-pubsub-policy.yaml"

	headers := map[string]string{
		"Host":          "orders.local",
		"Authorization": "Bearer " + newTestBearerToken(t),
	}

	buildURLs := func(base string) (publish, pull, ack, nack string) {
		publish = buildURL(base, "/v1alpha/publish")
		pull = buildURL(base, "/v1alpha/subscriptions/order-updates/pull")
		ack = buildURL(base, "/v1alpha/subscriptions/order-updates/ack")
		nack = buildURL(base, "/v1alpha/subscriptions/order-updates/nack")
		return
	}

	kubectlDeleteIgnoreNotFound(t, options, kubeResourcePath)

	// Phase 1: no policy -> rejected
	t.Run("phase=no-policy", func(t *testing.T) {
		for _, tg := range targets {
			t.Run("target="+tg.name, func(t *testing.T) {
				publishURL, pullURL, ackURL, nackURL := buildURLs(tg.baseURL)
				requireRejected(t, http.MethodPost, publishURL, headers)
				requireRejected(t, http.MethodPost, pullURL, headers)
				requireRejected(t, http.MethodPost, ackURL, headers)
				requireRejected(t, http.MethodPost, nackURL, headers)

				requireNotFound(t, http.MethodGet, publishURL, headers)
			})
		}
	})

	// Apply policy
	defer kubectlDeleteIgnoreNotFound(t, options, kubeResourcePath)
	k8s.KubectlApply(t, options, kubeResourcePath)

	// Phase 2: policy present -> allowed
	t.Run("phase=policy-applied", func(t *testing.T) {
		for _, tg := range targets {
			t.Run("target="+tg.name, func(t *testing.T) {
				publishURL, pullURL, ackURL, nackURL := buildURLs(tg.baseURL)
				requireOK(t, http.MethodPost, publishURL, headers)
				requireOK(t, http.MethodPost, pullURL, headers)
				requireOK(t, http.MethodPost, ackURL, headers)
				requireOK(t, http.MethodPost, nackURL, headers)

				requireNotFound(t, http.MethodGet, publishURL, headers)
			})
		}
	})

	// Remove policy
	k8s.KubectlDelete(t, options, kubeResourcePath)

	// Phase 3: policy removed -> rejected again
	t.Run("phase=policy-removed", func(t *testing.T) {
		for _, tg := range targets {
			t.Run("target="+tg.name, func(t *testing.T) {
				publishURL, pullURL, ackURL, nackURL := buildURLs(tg.baseURL)
				requireRejected(t, http.MethodPost, publishURL, headers)
				requireRejected(t, http.MethodPost, pullURL, headers)
				requireRejected(t, http.MethodPost, ackURL, headers)
				requireRejected(t, http.MethodPost, nackURL, headers)

				requireNotFound(t, http.MethodGet, publishURL, headers)
			})
		}
	})
}
