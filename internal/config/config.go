package config

import (
	"time"

	casbinkube "github.com/grepplabs/casbin-kube"
)

var (
	// Version is the current version of the app, generated at build time
	Version = "unknown"
)

const (
	AdapterFile = "file"
	AdapterKube = "kube"
)

type ServerConfig struct {
	Addr string
}
type Config struct {
	Server ServerConfig
	Casbin CasbinConfig
	Auth   AuthConfig
}

type AuthConfig struct {
	RouteConfigPath string
}

type CasbinConfig struct {
	Model                  string // if starts file:// then load from disk
	AutoLoadPolicyInterval time.Duration
	Adapter                string // adapter type: kube or file
	AdapterKube            CasbinAdapterKubeConfig
	AdapterFile            CasbinAdapterFileConfig
}

type CasbinAdapterKubeConfig struct {
	DisableInformer bool
	casbinkube.KubeConfig
}

type CasbinAdapterFileConfig struct {
	PolicyPath string
}
