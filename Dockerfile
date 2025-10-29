FROM --platform=${BUILDPLATFORM} golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION="unset"

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a \
        -ldflags="\
          -X 'github.com/grepplabs/casbin-traefik-forward-auth/internal/config.Version=${VERSION}' \
      " \
    -o casbin-traefik-forward-auth cmd/casbin-traefik-forward-auth/main.go

FROM --platform=${BUILDPLATFORM} gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/casbin-traefik-forward-auth .
USER 65532:65532

ENTRYPOINT ["/casbin-traefik-forward-auth"]
