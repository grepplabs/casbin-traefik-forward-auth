SHELL := /usr/bin/env bash
.SHELLFLAGS += -o pipefail -O extglob
.DEFAULT_GOAL := help

.PHONY: help
help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


up:
	docker compose up

up-d:
	docker compose up -d

down:
	docker compose down --remove-orphans --volumes

test:
	curl -u 'alice:passwrd' -v localhost:8080/alice_data/doc1

dashboard:
	google-chrome http://localhost:8081/dashboard
