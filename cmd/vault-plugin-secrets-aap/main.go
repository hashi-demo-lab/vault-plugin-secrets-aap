// Command vault-plugin-secrets-aap is the plugin entrypoint binary that Vault
// executes. It serves the AAP secrets engine backend over the plugin gRPC
// transport.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	aap "github.com/hashi-demo-lab/vault-plugin-secrets-aap"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})

	opts, err := serveOpts(os.Args[1:])
	if err != nil {
		logger.Error("failed to parse plugin flags", "error", err)
		os.Exit(1)
	}

	if err := plugin.ServeMultiplex(opts); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

// serveOpts parses the plugin API client flags and builds the ServeOpts that
// wire this plugin's Factory and TLS provider. Extracted from main so the wiring
// is unit-testable without actually serving over gRPC.
func serveOpts(args []string) (*plugin.ServeOpts, error) {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(args); err != nil {
		return nil, err
	}

	return &plugin.ServeOpts{
		BackendFactoryFunc: aap.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(apiClientMeta.GetTLSConfig()),
	}, nil
}
