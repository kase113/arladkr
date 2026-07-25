package core

// APVSSTranscript is the provider-neutral object passed between the
// distribution and verification stages.
type APVSSTranscript struct {
	Dealer       int
	Payload      []byte
	Ciphertexts  map[int][]byte
	DescriptorID []byte
}

// APVSSRecovered carries an explicit output type so callers cannot confuse a
// protocol-emulator digest or group element with scalar threshold-key output.
type APVSSRecovered struct {
	OutputKind          APVSSOutputKind
	AggregateDigest     []byte
	RecoveredMaterial   []byte
	ContributionDigests map[int][]byte
	ScalarThreshold     int
	ScalarShares        map[int][]byte
	ThresholdPublicKey  []byte
}

func cloneAPVSSRecovered(in *APVSSRecovered) *APVSSRecovered {
	if in == nil {
		return nil
	}
	return &APVSSRecovered{
		OutputKind:          in.OutputKind,
		AggregateDigest:     append([]byte(nil), in.AggregateDigest...),
		RecoveredMaterial:   append([]byte(nil), in.RecoveredMaterial...),
		ContributionDigests: cloneBytesMap(in.ContributionDigests),
		ScalarThreshold:     in.ScalarThreshold,
		ScalarShares:        cloneBytesMap(in.ScalarShares),
		ThresholdPublicKey:  append([]byte(nil), in.ThresholdPublicKey...),
	}
}

type APVSS interface {
	Capabilities() APVSSCapabilities
	ADist(cfg Config, art *DealerArtifact) (*APVSSTranscript, error)
	Ver(cfg Config, tx *APVSSTranscript, art *DealerArtifact) error
	Agg(cfg Config, dealers []int, artifacts map[int]*DealerArtifact) (*APVSSAggregate, error)
	AVer(cfg Config, agg *APVSSAggregate, artifacts map[int]*DealerArtifact) error
	Rec(cfg Config, agg *APVSSAggregate, artifacts map[int]*DealerArtifact) (*APVSSRecovered, error)
}

func newAPVSSFromConfig(cfg Config) APVSS {
	return &cvSAPVSSMaterializedProvider{}
}
