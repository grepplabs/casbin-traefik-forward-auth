SHELL := /usr/bin/env bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR       = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
VERSION       ?= $(shell git describe --tags --always --dirty)

TAG :=
CHART_FILE := charts/casbin-forward-auth/Chart.yaml

GOLANGCI_LINT_VERSION := v2.4.0

DOCKER_BUILD_ARGS ?=
LOCAL_IMAGE := local/casbin-forward-auth:latest
LOCAL_CLUSTER_ROOT_DIR ?= $(ROOT_DIR)/test/scripts/local/local-cluster
LOCAL_CLUSTER_NAME ?= casbin-traefik
LOCAL_KIND_CONFIG ?= $(ROOT_DIR)/kind-config-$(LOCAL_CLUSTER_NAME).yaml
LOCAL_KUBECONFIG ?= $(ROOT_DIR)/kubeconfig-$(LOCAL_CLUSTER_NAME)

LOCAL_CERT_DIR ?= $(ROOT_DIR)/test/scripts/certs/output

##@ General

.PHONY: help
help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

## Tool Binaries
GO_RUN := go run
GOLANGCI_LINT ?= $(GO_RUN) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: lint
lint: ## run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: ## run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: ## verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify


##@ Development

.PHONY: fmt
fmt: ## run go fmt against code
	go fmt ./...

.PHONY: vet
vet: ## run go vet against code
	go vet ./...

.PHONY: tidy
tidy: ## run go mod tidy
	go mod tidy

##@ Build

.PHONY: build
build: ## build binary
	go build -gcflags "all=-N -l" -o ./casbin-forward-auth ./cmd/casbin-forward-auth

.PHONY: clean
clean: local-cluster-delete ## clean
	rm -f ./casbin-forward-auth

##@ Docker

.PHONY: docker-build
docker-build: ## build docker image
	docker build --build-arg VERSION=$(VERSION) $(DOCKER_BUILD_ARGS) -t ${LOCAL_IMAGE} .

##@ Release

.PHONY: release
release: ## update helm chart version and appVersion and push tag
	@if [ -z "$(TAG)" ]; then \
		echo "TAG is required, e.g. 'make release TAG=v0.0.1'"; \
		exit 1; \
	fi
	@if ! echo "$(TAG)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Invalid TAG format: $(TAG). Must match v*.*.* (e.g. v1.2.3)"; \
		exit 1; \
	fi
	@if git rev-parse $(TAG) >/dev/null 2>&1; then \
		echo "Tag $(TAG) already exists. Aborting."; \
		exit 1; \
	fi
	@read -p "Are you sure you want to release $(TAG)? [y/N] " confirm; \
	if [ "$$confirm" != "y" ] && [ "$$confirm" != "Y" ] && [ "$$confirm" != "yes" ] && [ "$$confirm" != "YES" ]; then \
		echo "Aborted."; \
		exit 1; \
	fi;

	@echo "Updating Helm chart to version $(TAG)..."
	@yq eval -i '.version = "$(subst v,,$(TAG))"' $(CHART_FILE)
	@yq eval -i '.appVersion = "$(TAG)"' $(CHART_FILE)
	@echo "Chart.yaml updated:"
	@yq eval '.version, .appVersion' $(CHART_FILE)
	@git add $(CHART_FILE)
	@git commit -m "prepare release: bump chart version to $(TAG)" || echo "No changes to commit."

	@echo "Creating and pushing Git tag $(TAG)..."
	@git tag $(TAG)
	@git push origin HEAD
	@git push origin $(TAG)
	@echo "Done."

##@ Run targets

run-server: ## run server
	go run cmd/casbin-forward-auth/main.go --auth-route-config-path=examples/pubsub-routes-expr.yaml

run-tls-server: ## run TLS server
	go run cmd/casbin-forward-auth/main.go --auth-route-config-path=examples/pubsub-routes-expr.yaml \
		--server-addr=":8448" \
		--server-admin-port=8081 \
		--server-tls-enable \
		--server-tls-refresh=10s \
		--server-tls-file-key=$(LOCAL_CERT_DIR)/casbin-auth-server-key.pem \
		--server-tls-file-cert=$(LOCAL_CERT_DIR)/casbin-auth-server.pem

build-run-server: build ## build and run server
	./casbin-forward-auth --auth-route-config-path=examples/pubsub-routes-expr.yaml

##@ Local cluster

.PHONY: local-cluster-create
local-cluster-create:  ## create local kind cluster
	USER_HOME="$(HOME)" yq 'with(.nodes[].extraMounts; . += [{"containerPath": "/var/lib/kubelet/config.json", "hostPath": strenv(USER_HOME) + "/.docker/config.json"}])' \
		< "$(LOCAL_CLUSTER_ROOT_DIR)/kind-config.yaml" > "$(LOCAL_KIND_CONFIG)"
	kind create cluster --name "${LOCAL_CLUSTER_NAME}" --config "${LOCAL_KIND_CONFIG}" --kubeconfig "${LOCAL_KUBECONFIG}" \
	  || (echo "Cluster may already exist, waiting for it to become ready..."; \
		  KUBECONFIG="${LOCAL_KUBECONFIG}" kubectl wait --for=condition=Ready nodes --all --timeout=120s)

.PHONY: local-cluster-delete
local-cluster-delete:  ## delete local kind cluster
	rm -f $(LOCAL_KIND_CONFIG)
	rm -f $(LOCAL_KUBECONFIG)
	kind delete cluster --name $(LOCAL_CLUSTER_NAME)

.PHONY: local-apply
local-apply: export KUBECONFIG=$(LOCAL_KUBECONFIG)
local-apply:
	kind load docker-image --name ${LOCAL_CLUSTER_NAME} local/casbin-forward-auth:latest
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR)/../crds --enable-helm | kubectl apply --server-side=true -f -
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR)/../traefik-crds --enable-helm | kubectl apply --server-side=true -f -
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR) --enable-helm | kubectl apply --server-side=true -f -
	- kubectl delete pod -n casbin-auth --all
	kubectl wait --for=condition=available deployment --all -A --timeout=300s

.PHONY: local-deploy
local-deploy: docker-build local-apply ## deploy to local kind cluster

.PHONY: local-init
local-init: local-cluster-create local-deploy ## init local cluster

##@ Test targets

.PHONY: test
test: ## run tests
	go test -v -race -count=1 ./...

.PHONY: benchmark
benchmark: ## run benchmarks
	go test -bench=. -benchmem ./...

.PHONY: helm-unittest
helm-unittest: ## run helm unittest
	@# helm plugin install https://github.com/helm-unittest/helm-unittest.git --version v1.0.3
	helm unittest charts/casbin-forward-auth

##@ Examples targets

TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY21lL3Byb2plY3QvcHJvamVjdC5pZCI6IjEyMzQ1Njc4OTAxMiIsImF1ZCI6WyJhY21lIiwiYXBpIl0sImF6cCI6Im1pY2hhbC10ZXN0LWFvZXlkODFAc2EuYWNtZS5jbG91ZCIsImVtYWlsIjoibWljaGFsLXRlc3QtYW9leWQ4MUBzYS5hY21lLmNsb3VkIiwiZXhwIjoxNzYwMDMzNTczLCJpYXQiOjE3NjAwMjk5NzMsImlzcyI6ImFjbWUvc2VydmljZWFjY291bnQiLCJqdGkiOiJhMDM5MjNjMS01ZTk5LTQ4OGEtYmQxYS1lMjAxYWY5NTZkMTciLCJzdWIiOiI5ZTRmZGIxYy0zMzQ1LTRjMDctOThkOS03M2I5OTNjOWRkNDIifQ.7In_S9Llms9H_WuBSDLKhEMS-Pk_6U5y-lNrz-rxuU8

example-grant: ## grant access
	kubectl apply -f examples/pubsub-policy.yaml

example-revoke: ## revoke access
	kubectl delete -f examples/pubsub-policy.yaml

example-publish: ## publish data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/publish" localhost:8080/v1/auth

example-read: ## read data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/pull" localhost:8080/v1/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/ack" localhost:8080/v1/auth
	curl -v -H "Authorization: Bearer $(TOKEN)" -H "X-Forwarded-Method: POST" -H "X-Forwarded-Host: orders.localhost" -H "X-Forwarded-Uri: /v1alpha/subscriptions/order-updates/nack" localhost:8080/v1/auth

example-all: example-grant example-publish example-read example-revoke

##@ E2E examples

E2E_TESTDATA_DIR := test/e2e/testdata/

e2e-grant: export KUBECONFIG=$(LOCAL_KUBECONFIG)
e2e-grant: ## grant access
	kubectl apply -f $(E2E_TESTDATA_DIR)/rbac-echo-pubsub-policy.yaml

e2e-revoke: export KUBECONFIG=$(LOCAL_KUBECONFIG)
e2e-revoke: ## revoke access
	kubectl delete -f $(E2E_TESTDATA_DIR)/rbac-echo-pubsub-policy.yaml

e2e-publish: ## publish data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: orders.local' -X POST http://localhost:30080/v1alpha/publish

e2e-read: ## read data
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: orders.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/pull
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: orders.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/ack
	curl -v -H "Authorization: Bearer $(TOKEN)" -H 'Host: orders.local' -X POST http://localhost:30080/v1alpha/subscriptions/order-updates/nack

e2e-all: e2e-grant e2e-publish e2e-read e2e-revoke

##@ E2E tests

.PHONY: test-e2e
test-e2e: local-init e2e-test ## init local cluster and run the e2e tests

.PHONY: e2e-test
e2e-test: ## run the e2e tests
	cd test/e2e && go test -v -count=1 ./...
