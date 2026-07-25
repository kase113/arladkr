package core

import "fmt"

type APVSSOutputKind string

const (
	APVSSOutputEmulated APVSSOutputKind = "emulated"
	APVSSOutputGroup    APVSSOutputKind = "group-element"
	APVSSOutputScalar   APVSSOutputKind = "scalar"
)

type APVSSCapabilities struct {
	OutputKind                 APVSSOutputKind
	VerifiesReceivedTranscript bool
	AggregatesReceivedInputs   bool
	ProducesVerifiableShares   bool
	UsesProductionRandomness   bool
	SupportsThresholdKeyOutput bool
	SecurityProfile            string
}

func (o *OptrandAPVSS) Capabilities() APVSSCapabilities {
	return APVSSCapabilities{
		OutputKind:      APVSSOutputEmulated,
		SecurityProfile: "protocol-emulator",
	}
}

func (p *BlsPVSSProvider) Capabilities() APVSSCapabilities {
	return APVSSCapabilities{
		OutputKind:                 APVSSOutputGroup,
		VerifiesReceivedTranscript: true,
		AggregatesReceivedInputs:   true,
		SecurityProfile:            "group-element-prototype",
	}
}

func APVSSCapabilitiesForConfig(cfg Config) APVSSCapabilities {
	return (&cvSAPVSSMaterializedProvider{}).Capabilities()
}

type apvssCapabilityProvider interface {
	Capabilities() APVSSCapabilities
}

func validateAPVSSDeriveMode(cfg Config, provider apvssCapabilityProvider) error {
	if cfg.DeriveMode != "scalar" {
		return nil
	}
	caps := provider.Capabilities()
	if caps.OutputKind != APVSSOutputScalar ||
		!caps.VerifiesReceivedTranscript ||
		!caps.AggregatesReceivedInputs ||
		!caps.ProducesVerifiableShares ||
		!caps.SupportsThresholdKeyOutput {
		return fmt.Errorf(
			"derive mode scalar requires scalar-output APVSS with verified inputs and shares; provider=%s profile=%s",
			cfg.APVSSProvider,
			caps.SecurityProfile,
		)
	}
	return nil
}
