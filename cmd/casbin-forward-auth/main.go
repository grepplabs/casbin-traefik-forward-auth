package main

import (
	"flag"
	"os"
	"time"

	"github.com/grepplabs/casbin-forward-auth/internal/config"
	"github.com/grepplabs/casbin-forward-auth/internal/server"
	"github.com/grepplabs/loggo/zlog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var cfg config.Config

// nolint:funlen
func main() {
	root := &cobra.Command{
		Use:   "server",
		Short: "casbin-forward-auth",
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
	config.BindFlagsToViper(root)

	// server flags
	root.Flags().StringVar(&cfg.Server.Addr, "server-addr", ":8080", "Server listen address.")
	root.Flags().IntVar(&cfg.Server.AdminPort, "server-admin-port", 0, "Admin server port (0 to disable).")

	root.Flags().BoolVar(&cfg.Server.TLS.Enable, "server-tls-enable", false, "Enable server-side TLS.")
	root.Flags().DurationVar(&cfg.Server.TLS.Refresh, "server-tls-refresh", 0, "Interval for refreshing server TLS certificates. Set to 0 to disable auto-refresh.")
	root.Flags().StringVar(&cfg.Server.TLS.KeyPassword, "server-tls-key-password", "", "Password to decrypt RSA private key.")
	root.Flags().StringVar(&cfg.Server.TLS.File.Key, "server-tls-file-key", "", "Path to the server TLS private key file.")
	root.Flags().StringVar(&cfg.Server.TLS.File.Cert, "server-tls-file-cert", "", "Path to the server TLS certificate file.")
	root.Flags().StringVar(&cfg.Server.TLS.File.ClientCAs, "server-tls-file-client-ca", "", "Path to the server client CA file for client verification.")
	root.Flags().StringVar(&cfg.Server.TLS.File.ClientCRL, "server-tls-file-client-crl", "", "Path to the TLS X509 CRL signed by the client CA. If unspecified, only the client CA is verified.")

	// metrics
	root.Flags().BoolVar(&cfg.Metrics.IncludeHost, "metrics-include-host", false, "Include HTTP Host header as a Prometheus label (can increase cardinality).")

	// auth flags
	root.Flags().StringVar(&cfg.Auth.RouteConfigPath, "auth-route-config-path", "", "Path to the config YAML file containing route authorization rules.")

	// casbin flags
	root.Flags().StringVar(&cfg.Casbin.Model, "casbin-model", "rbac_model.conf", "Path or reference to the Casbin model (e.g. file:///etc/casbin/model.conf or rbac_model.conf from embedded FS).")
	root.Flags().StringVar(&cfg.Casbin.Adapter, "casbin-adapter", "kube", "Casbin adapter. One of: file, kube.")
	root.Flags().DurationVar(&cfg.Casbin.AutoLoadPolicyInterval, "casbin-autoload-interval", 0, "Interval for automatically reloading Casbin policies (e.g. 30s, 1m). Set to 0 to disable.")
	/// casbin file adapter
	root.Flags().StringVar(&cfg.Casbin.AdapterFile.PolicyPath, "casbin-adapter-file-policy-path", "examples/rbac_policy.csv", "Path to the policy file.")
	/// casbin  kube adapter
	root.Flags().BoolVar(&cfg.Casbin.AdapterKube.DisableInformer, "casbin-adapter-kube-disable-informer", false, "Disable the Casbin Kubernetes informer.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Context, "casbin-adapter-kube-config-context", "", "Name of the Kubernetes context to use from the kubeconfig file.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Namespace, "casbin-adapter-kube-config-namespace", os.Getenv("POD_NAMESPACE"), "Kubernetes namespace where Casbin policies are stored.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Path, "casbin-adapter-kube-config-path", "", "Path to the kubeconfig file.")
	root.Flags().StringToStringVar(&cfg.Casbin.AdapterKube.Labels, "casbin-adapter-kube-config-labels", nil, "Labels to filter policies. Example: key1=val1,key2=val2.")

	/// jwt flags
	root.Flags().BoolVar(&cfg.Auth.JWTConfig.Enabled, "jwt-enabled", false, "Enable JWT verification for incoming requests. When enabled, 'jwt-jwks-url', 'jwt-issuer', and 'jwt-audience' must be set.")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.JWKSURL, "jwt-jwks-url", "", "URL or file path to the JWKS source (e.g., https://issuer.example.com/.well-known/jwks.json or file:///etc/jwks/keys.json).")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.Issuer, "jwt-issuer", "", "Expected JWT issuer ('iss' claim).")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.Audience, "jwt-audience", "", "Expected JWT audience ('aud' claim).")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.Skew, "jwt-skew", 0, "Clock skew tolerance for exp/nbf claims (e.g. 30s).")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.InitTimeout, "jwt-init-timeout", 15*time.Second, "Maximum time to wait for initial JWKS fetch during startup.")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.RefreshTimeout, "jwt-refresh-timeout", 2*time.Second, "Timeout for individual JWKS refresh requests.")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.MinRefreshInterval, "jwt-min-refresh-interval", 0, "Minimum interval between JWKS refresh attempts.")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.MaxRefreshInterval, "jwt-max-refresh-interval", 0, "Maximum interval between JWKS refresh attempts.")
	root.Flags().BoolVar(&cfg.Auth.JWTConfig.UseX509, "jwt-use-x509", false, "Indicates that the JWKS source contains X.509-encoded keys (PEM certificates) instead of standard JWK JSON.")

	root.Flags().BoolVar(&cfg.Auth.JWTConfig.TLS.Enable, "jwt-tls-enable", false, "Enable TLS configuration for the JWKS HTTPS client.")
	root.Flags().DurationVar(&cfg.Auth.JWTConfig.TLS.Refresh, "jwt-tls-refresh", 0, "Interval for reloading client TLS certificates. Set to 0 to disable auto-refresh.")
	root.Flags().BoolVar(&cfg.Auth.JWTConfig.TLS.InsecureSkipVerify, "jwt-tls-insecure-skip-verify", false, "Skip server certificate verification (insecure; use only for testing).")
	root.Flags().BoolVar(&cfg.Auth.JWTConfig.TLS.UseSystemPool, "jwt-tls-use-system-pool", true, "Use the system certificate pool for verifying server certificates.")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.TLS.KeyPassword, "jwt-tls-key-password", "", "Password to decrypt RSA private key.")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.TLS.File.RootCAs, "jwt-tls-file-root-ca", "", "Path to a custom root CA bundle for verifying the JWKS server.")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.TLS.File.Key, "jwt-tls-file-key", "", "Path to the client TLS private key file (for mTLS).")
	root.Flags().StringVar(&cfg.Auth.JWTConfig.TLS.File.Cert, "jwt-tls-file-cert", "", "Path to the client TLS certificate file (for mTLS).")

	// Merge stdlib flags into pflag (so Cobra can see them)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	if err := root.Execute(); err != nil {
		zlog.Fatalw("execution error", "error", err)
	}
}

func run() {
	zlog.Infof("running")
	err := server.Start(cfg)
	if err != nil {
		zlog.Fatalw("problem running server", "error", err)
	}
}
