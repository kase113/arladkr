package core

import (
	"fmt"
	"strings"
)

func newAgreementTransport(cfg Config, nodes []int, buffer int) (agreementTransport, error) {
	localNodes := append([]int(nil), cfg.LocalNodeIDs...)
	if strings.EqualFold(strings.TrimSpace(cfg.APVSSProvider), "cv-sapvss") {
		localNodes = sortedUnique(append(localNodes, cfg.CVLocalReceiverIDs...))
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.AgreementTransport))
	switch mode {
	case "":
		return NewTCPLoopbackTransportWithOptions(
			cfg,
			nodes,
			localNodes,
			buffer,
			cfg.AgreementBindHost,
			cfg.AgreementBasePort,
		)
	case "tcp-loopback", "tcp", "tcp-distributed":
		return NewTCPLoopbackTransportWithOptions(
			cfg,
			nodes,
			localNodes,
			buffer,
			cfg.AgreementBindHost,
			cfg.AgreementBasePort,
		)
	default:
		return nil, fmt.Errorf("unsupported agreement transport: %s", cfg.AgreementTransport)
	}
}
