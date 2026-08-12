package core

import (
	"bytes"
	"fmt"
)

const (
	cvAgreementObjectV2Domain   = "ARL-CV-sAPVSS/v2-scalar-group/agreement-object"
	cvMaxAgreementObjectV2Bytes = cvMaxNetworkPayloadBytes
)

type cvAgreementObjectV2 struct {
	Header          cvAggregateHeaderV2
	Pool            cvPoolV2
	PoolCert        cvPoolCertificateV2
	ContributorCoin cvCoinOutputV2
	SelectedIndices []int
	VCert           cvValidationCertificateV2
	ARC             cvAPDBLockV2
}

type cvAgreementPublicContextV2 struct {
	SID             string
	Epoch           uint64
	ContextDigest   []byte
	OldCommittee    []int
	EligibilityCoin *cvCoinOutputV2
	Params          cvV2Params
	APDBSigner      *tblsThresholdSigner
	ControlSigner   *tblsThresholdSigner
	CoinSigner      *tblsThresholdSigner
	ValidatorKeys   *cvValidatorKeyMaterialV2
}

func cvAgreementObjectV2CanonicalBytes(object *cvAgreementObjectV2, params cvV2Params, validatorSample []int) ([]byte, error) {
	if object == nil || len(object.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 agreement object")
	}
	headerWire, err := cvAggregateHeaderV2CanonicalBytes(&object.Header)
	if err != nil {
		return nil, err
	}
	poolWire, err := cvPoolV2CanonicalBytes(&object.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCertWire, err := cvPoolCertificateV2CanonicalBytes(&object.PoolCert)
	if err != nil {
		return nil, err
	}
	coinWire, err := cvCoinOutputV2CanonicalBytes(&object.ContributorCoin)
	if err != nil {
		return nil, err
	}
	vCertWire, err := cvValidationCertificateV2CanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := cvAPDBLockV2CanonicalBytes(&object.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAgreementObjectV2Domain))
	for _, nested := range [][]byte{headerWire, poolWire, poolCertWire, coinWire} {
		_ = cvWriteBytes(&wire, nested)
	}
	_ = cvWriteUint32(&wire, len(object.SelectedIndices))
	for _, index := range object.SelectedIndices {
		if index < 0 || index >= params.poolSize {
			return nil, fmt.Errorf("invalid CV V2 selected pool index")
		}
		cvWriteUint64(&wire, uint64(index))
	}
	_ = cvWriteBytes(&wire, vCertWire)
	_ = cvWriteBytes(&wire, arcWire)
	if wire.Len() > cvMaxAgreementObjectV2Bytes {
		return nil, fmt.Errorf("CV V2 agreement object exceeds wire limit")
	}
	return wire.Bytes(), nil
}

func cvDecodeAgreementObjectV2(wire []byte, params cvV2Params, validatorSample []int) (*cvAgreementObjectV2, error) {
	if len(wire) == 0 || len(wire) > cvMaxAgreementObjectV2Bytes {
		return nil, fmt.Errorf("invalid CV V2 agreement object wire size")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAgreementObjectV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvAgreementObjectV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 agreement object domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxAgreementObjectV2Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 agreement object field")
		}
	}
	header, err := cvDecodeAggregateHeaderV2(nested[0])
	if err != nil {
		return nil, err
	}
	pool, err := cvDecodePoolV2(nested[1], params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvDecodePoolCertificateV2(nested[2])
	if err != nil {
		return nil, err
	}
	coin, err := cvDecodeCoinOutputV2(nested[3])
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 agreement selection count")
	}
	selected := make([]int, count)
	for i := range selected {
		value, readErr := r.uint64()
		if readErr != nil || value >= uint64(params.poolSize) {
			return nil, fmt.Errorf("invalid CV V2 agreement selected index")
		}
		selected[i] = int(value)
	}
	vCertWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 agreement VCert")
	}
	vCert, err := cvDecodeValidationCertificateV2(vCertWire, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 agreement ARC")
	}
	arc, err := cvDecodeAPDBLockV2(arcWire)
	if err != nil {
		return nil, err
	}
	object := &cvAgreementObjectV2{Header: *header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *coin,
		SelectedIndices: selected, VCert: *vCert, ARC: *arc}
	canonical, err := cvAgreementObjectV2CanonicalBytes(object, params, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 agreement object")
	}
	return object, nil
}

// cvVerifyAgreementObjectV2 is the public MVBA predicate core. It deliberately
// has no APDB store, component cache, recovery callback, or mutable slot state.
func cvVerifyAgreementObjectV2(object *cvAgreementObjectV2, public cvAgreementPublicContextV2) error {
	proposers, validators, err := cvAgreementEligibilitySamplesV2(public)
	if object == nil || err != nil || len(public.ContextDigest) != 32 || !cvV2SignerHasRole(public.APDBSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(public.ControlSigner, cvV2RoleControl) || !cvV2SignerHasRole(public.CoinSigner, cvV2RoleCoin) || public.ValidatorKeys == nil {
		return fmt.Errorf("invalid CV V2 agreement public context")
	}
	if _, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators); err != nil {
		return err
	}
	if !bytes.Equal(object.Header.ContextDigest, public.ContextDigest) || !bytes.Equal(object.Pool.ContextDigest, public.ContextDigest) ||
		object.Header.ProposerID != object.Pool.ProposerID || !cvContainsID(proposers, object.Header.ProposerID) {
		return fmt.Errorf("invalid CV V2 agreement proposer or context")
	}
	if !bytes.Equal(object.Header.PoolDigest, object.Pool.Digest) {
		return fmt.Errorf("CV V2 agreement pool/header mismatch")
	}
	for i := range object.Pool.Components {
		if err := cvValidateComponentRefV2(object.Pool.Components[i], public.APDBSigner); err != nil {
			return fmt.Errorf("invalid CV V2 agreement component lock: %w", err)
		}
	}
	if err := cvVerifyPoolCertificateV2(&object.Pool, &object.PoolCert, public.ControlSigner); err != nil {
		return err
	}
	expectedInvocation, err := cvContributorCoinInvocationV2(public.ContextDigest, object.Header.ProposerID, object.Pool.Digest)
	if err != nil || cvVerifyCoinOutputV2(&object.ContributorCoin, expectedInvocation, public.CoinSigner) != nil {
		return fmt.Errorf("invalid CV V2 agreement contributor coin")
	}
	wantSelection, err := cvSelectedPoolIndicesV2(public.Params.poolSize, public.Params.componentCount, object.ContributorCoin.Value)
	if err != nil || !equalInts(wantSelection, object.SelectedIndices) {
		return fmt.Errorf("invalid CV V2 agreement contributor selection")
	}
	selectionDigest, err := cvSelectionDigestV2(&object.ContributorCoin, object.SelectedIndices, public.Params.poolSize, public.Params.componentCount)
	if err != nil || !bytes.Equal(selectionDigest, object.Header.SelectionDigest) {
		return fmt.Errorf("invalid CV V2 agreement selection digest")
	}
	if err := cvVerifyValidationCertificateV2(&object.VCert, &object.Header, validators, public.Params.validatorThreshold, public.ValidatorKeys); err != nil {
		return err
	}
	if !bytes.Equal(object.ARC.InstanceDigest, object.Header.APDBInstance) || !bytes.Equal(object.ARC.Root, object.Header.APDBRoot) {
		return fmt.Errorf("CV V2 agreement ARC/header mismatch")
	}
	if err := cvVerifyAPDBLockV2(&object.ARC, public.APDBSigner); err != nil {
		return err
	}
	return nil
}

func cvAggregatePredicateV2(public cvAgreementPublicContextV2) func(int, []byte) bool {
	return func(_ int, candidate []byte) bool {
		_, validators, err := cvAgreementEligibilitySamplesV2(public)
		if err != nil {
			return false
		}
		object, err := cvDecodeAgreementObjectV2(candidate, public.Params, validators)
		return err == nil && cvVerifyAgreementObjectV2(object, public) == nil
	}
}

func cvAgreementEligibilitySamplesV2(public cvAgreementPublicContextV2) ([]int, []int, error) {
	if public.SID == "" || public.Epoch == 0 || public.EligibilityCoin == nil || public.CoinSigner == nil ||
		len(public.OldCommittee) == 0 || !equalInts(public.OldCommittee, sortedUnique(public.OldCommittee)) {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility context")
	}
	expectedInvocation, err := cvEligibilityCoinInvocationV2(public.SID, public.Epoch)
	if err != nil || cvVerifyCoinOutputV2(public.EligibilityCoin, expectedInvocation, public.CoinSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesV2(
		public.OldCommittee, public.EligibilityCoin.Value, public.Params.proposerSampleSize, public.Params.validatorSampleSize,
	)
	if err != nil || !cvValidValidatorSampleV2(validators, public.ValidatorKeys) {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility samples")
	}
	return proposers, validators, nil
}

func cvContainsID(ids []int, target int) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
