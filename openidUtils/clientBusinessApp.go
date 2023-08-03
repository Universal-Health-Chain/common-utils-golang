package openidUtils

// OpenidClientAppConfig
// TODO: ClientID will be always the ReverseDNS?
type OpenidClientAppConfig struct {
	ClientID   string
	ReverseDNS string
	Config     OpenidProviderAppMetadata
}
