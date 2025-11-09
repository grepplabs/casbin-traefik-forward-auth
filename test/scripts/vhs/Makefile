SHELL := /usr/bin/env bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

ROOT_DIR       = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_DIR    = $(realpath $(ROOT_DIR)/../../..)

LOCAL_IMAGE := local/casbin-forward-auth:latest
LOCAL_CLUSTER_ROOT_DIR ?= $(ROOT_DIR)/local/local-cluster
LOCAL_CLUSTER_NAME ?= casbin-vhs
LOCAL_KIND_CONFIG ?= $(ROOT_DIR)/kind-config-$(LOCAL_CLUSTER_NAME).yaml
LOCAL_KUBECONFIG ?= $(ROOT_DIR)/kubeconfig-$(LOCAL_CLUSTER_NAME)

.PHONY: help
help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ General

.PHONY: clean
clean: local-cluster-delete ## clean

.PHONY: docker-build
docker-build:
	cd $(PROJECT_DIR) && make docker-build

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
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR)/../traefik-crds --enable-helm | kubectl apply --server-side=true -f -
	kubectl kustomize $(LOCAL_CLUSTER_ROOT_DIR) --enable-helm | kubectl apply --server-side=true -f -
	- kubectl delete pod -n casbin-auth --all
	kubectl wait --for=condition=available deployment --all -A --timeout=300s

.PHONY: local-deploy
local-deploy: docker-build local-apply ## deploy to local kind cluster

local-init: local-cluster-create local-deploy ## init local cluster

##@ Keycloak
kc-create-alice: export KUBECONFIG=$(LOCAL_KUBECONFIG)
kc-create-alice:
	./kc-create-user.sh alice alicepw

kc-create-bob: export KUBECONFIG=$(LOCAL_KUBECONFIG)
kc-create-bob:
	./kc-create-user.sh bob bobpw

kc-create-client: export KUBECONFIG=$(LOCAL_KUBECONFIG)
kc-create-client:
	./kc-create-client.sh local-cli-client

KC_USERNAME=""
KC_PASSWORD=""

kc-get-token:
	@curl -s \
	  -d "grant_type=password" \
	  -d "client_id=local-cli-client" \
	  -d "username=$(KC_USERNAME)" \
	  -d "password=$(KC_PASSWORD)" \
	  http://localhost:30082/realms/master/protocol/openid-connect/token | jq -r '.access_token'

get-alice-token: KC_USERNAME=alice
get-alice-token: KC_PASSWORD=alicepw
get-alice-token: kc-get-token

get-bob-token: KC_USERNAME=bob
get-bob-token: KC_PASSWORD=bobpw
get-bob-token: kc-get-token

.PHONY: kc-init
kc-init: kc-create-client kc-create-alice kc-create-bob get-alice-token get-bob-token

##@ Test

.PHONY: curl-test
curl-test:
	curl -I -X GET http://echo.127.0.0.1.nip.io:30081/alice_data/resource3

.PHONY: curl-test-alice
curl-test-alice:
	@TOKEN=$$($(MAKE) -s get-alice-token); \
	if [ -z "$$TOKEN" ]; then \
	  echo "ERROR: token is empty" >&2; exit 1; \
	fi; \
	curl -I --oauth2-bearer "$${TOKEN}" -X GET http://echo.127.0.0.1.nip.io:30081/alice_data/resource3

.PHONY: curl-test-bob
curl-test-bob:
	@TOKEN=$$($(MAKE) -s get-bob-token); \
	if [ -z "$$TOKEN" ]; then \
	  echo "ERROR: token is empty" >&2; exit 1; \
	fi; \
	curl -I --oauth2-bearer "$${TOKEN}" -X GET http://echo.127.0.0.1.nip.io:30081/alice_data/resource3

.PHONY: oidc-test
oidc-test:
	curl http://localhost:30082/realms/master/protocol/openid-connect/certs | jq '.'

enable-forward-auth:
	kubectl annotate ingress echo \
	  -n default \
	  "traefik.ingress.kubernetes.io/router.middlewares=traefik-casbin-auth@kubernetescrd" \
	  --overwrite

disable-forward-auth:
	kubectl annotate ingress echo -n default traefik.ingress.kubernetes.io/router.middlewares-

show-config:
	cat local/casbin-forward-auth/values.yaml

show-policy:
	curl -s https://raw.githubusercontent.com/casbin/casbin/refs/heads/master/examples/keymatch_policy.csv

show-convert:
	casbin-kube-converter -i https://raw.githubusercontent.com/casbin/casbin/refs/heads/master/examples/keymatch_policy.csv -n casbin-auth | tail -20

# Uses https://github.com/mike-engel/jwt-cli/
show-claims-alice:
	@TOKEN=$$($(MAKE) -s get-alice-token); \
		jwt decode "$$TOKEN" --json | jq -r '.payload'

apply-rules: export KUBECONFIG=$(LOCAL_KUBECONFIG)
apply-rules:
	casbin-kube-converter -i https://raw.githubusercontent.com/casbin/casbin/refs/heads/master/examples/keymatch_policy.csv -n casbin-auth | kubectl apply -f-

delete-rules: export KUBECONFIG=$(LOCAL_KUBECONFIG)
delete-rules:
	- casbin-kube-converter -i https://raw.githubusercontent.com/casbin/casbin/refs/heads/master/examples/keymatch_policy.csv -n casbin-auth | kubectl delete -f-

show-rules:
	kubectl get rules.casbin.grepplabs.com -A

##@ VHS

vhs-prepare: kc-init disable-forward-auth delete-rules

vhs-record: export KUBECONFIG=$(LOCAL_KUBECONFIG)
vhs-record: demo-keymatch.tape
	#@export TOKEN=$$($(MAKE) -s get-alice-token); \
	vhs demo-keymatch.tape
	google-chrome demo-keymatch.gif

.PHONY: demo-keymatch.tape
demo-keymatch.tape:
	@cat $(sort $(wildcard  demo-keymatch/*.part)) > $@
