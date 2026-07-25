package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssLaneStatementDomain = "ARL-APVSS-v1/lane-statement"
	apvssACKChallengeDomain  = "ARL-APVSS-v1/receiver-ack"
	apvssFallbackDomain      = "ARL-APVSS-v1/exact-lane-fallback"
	apvssLeafDigestDomain    = "ARL-APVSS-v1/leaf"
	apvssLeafWireDomain      = "ARL-APVSS-v1/leaf-wire"
	apvssACKMessageDomain    = "ARL-APVSS-v1/ack-message"
)

type apvssSchnorrSignatureV1 struct {
	r bls12381.G1Affine
	z fr.Element
}

type apvssLaneACKV1 struct {
	receiverIndex int
	signature     apvssSchnorrSignatureV1
}

type apvssFallbackProofV1 struct {
	receiverIndex int
	proof         *cvLeafProofV1
}

// apvssLeafPrototypeV1 deliberately wraps a structural CV leaf. The network
// codec remains unchanged until this proof/ACK split has been benchmarked.
type apvssLeafPrototypeV1 struct {
	leaf           *cvLeafV1
	acks           []apvssLaneACKV1
	fallbackProofs []apvssFallbackProofV1
	digest         []byte
}

type apvssLaneACKMessageV1 struct {
	dealerID   uint64
	leafDigest []byte
	ack        apvssLaneACKV1
}

type apvssDealerWitnessV1 struct {
	scalars       []fr.Element
	blindings     []fr.Element
	scalarCoins   [][]fr.Element
	blindingCoins []fr.Element
}

func apvssValidateStructuralLeafV1(context *cvLeafContextV1, leaf *cvLeafV1) error {
	if context == nil || context.proofProfile != cvLeafV1StructuralProofProfile {
		return fmt.Errorf("APVSS base leaf must use the structural proof profile")
	}
	return cvVerifyLeafV1(context, leaf)
}

func apvssLaneV1(leaf *cvLeafV1, receiverIndex int) (*cvLeafReceiverV1, error) {
	if leaf == nil || receiverIndex <= 0 || receiverIndex > len(leaf.receivers) {
		return nil, fmt.Errorf("APVSS receiver index outside leaf")
	}
	lane := &leaf.receivers[receiverIndex-1]
	if lane.receiverIndex != receiverIndex {
		return nil, fmt.Errorf("APVSS receiver lane index mismatch")
	}
	return lane, nil
}

// apvssDecryptLaneStrictV1 differs from cvDecryptShare in one security-critical
// respect: it rejects a reconstructed integer outside [0,q), rather than
// reducing it modulo q. ACKs must only be issued for canonical digit encodings.
func apvssDecryptLaneStrictV1(
	profile cvChunkProfile,
	receiverSecret fr.Element,
	share *cvEncryptedShare,
) (*cvDecryptedShare, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if err := cvValidateShare(share, chunks); err != nil {
		return nil, err
	}
	receiverPK, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		return nil, err
	}
	if !receiverPK.Equal(&share.receiverPublicKey) {
		return nil, fmt.Errorf("APVSS receiver secret does not match lane key")
	}

	secretInt := receiverSecret.BigInt(new(big.Int))
	solver := cvNewBoundedDLogSolver(base - 1)
	integerScalar := new(big.Int)
	for i := range share.scalarChunks {
		chunk := &share.scalarChunks[i]
		var shared, message bls12381.G1Affine
		shared.ScalarMultiplication(&chunk.r, secretInt)
		message.Sub(&chunk.c, &shared)
		digit, ok := solver.solve(&message)
		if !ok {
			return nil, fmt.Errorf("APVSS bounded DLog failed for chunk %d", i)
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(i)*profile.chunkBits)
		integerScalar.Add(integerScalar, term)
	}
	if integerScalar.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("APVSS scalar digits are not a canonical field encoding")
	}

	var scalar fr.Element
	scalar.SetBigInt(integerScalar)
	var blindingShared, blindingOpening, publicScalar bls12381.G1Affine
	blindingShared.ScalarMultiplication(&share.blinding.r, secretInt)
	blindingOpening.Sub(&share.blinding.c, &blindingShared)
	publicScalar.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
	decrypted := &cvDecryptedShare{
		scalar:          scalar,
		publicScalar:    publicScalar,
		blindingOpening: blindingOpening,
	}
	if !cvVerifyRelation(share, decrypted) {
		return nil, fmt.Errorf("APVSS decrypted lane does not open its Pedersen evaluation")
	}
	return decrypted, nil
}

func apvssLaneStatementBytesV1(leaf *cvLeafV1, receiverIndex int) ([]byte, error) {
	lane, err := apvssLaneV1(leaf, receiverIndex)
	if err != nil {
		return nil, err
	}
	if err := cvValidateLeafContextV1(&leaf.context); err != nil {
		return nil, err
	}
	if len(leaf.receivers) != len(leaf.context.receiverPublicKeys) {
		return nil, fmt.Errorf("APVSS receiver registry length mismatch")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	if len(leaf.coefficientCommitments) != leaf.context.sharingDegree+1 {
		return nil, fmt.Errorf("APVSS coefficient commitment count mismatch")
	}
	if err := cvValidateShare(lane.encryptedShare, chunks); err != nil {
		return nil, err
	}
	if !lane.receiverPublicKey.Equal(&leaf.context.receiverPublicKeys[receiverIndex-1]) ||
		!lane.encryptedShare.receiverPublicKey.Equal(&lane.receiverPublicKey) {
		return nil, fmt.Errorf("APVSS receiver key binding mismatch")
	}
	expectedCommitment := cvEvaluateCommitmentsV1(leaf.coefficientCommitments, receiverIndex)
	if !lane.encryptedShare.commitment.Equal(&expectedCommitment) {
		return nil, fmt.Errorf("APVSS lane commitment is not the polynomial evaluation")
	}
	contextDigest := cvLeafContextV1Digest(&leaf.context)
	if len(contextDigest) == 0 {
		return nil, fmt.Errorf("encode APVSS context")
	}

	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssLaneStatementDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, contextDigest); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, leaf.dealerID)
	if err := cvWriteUint32(&wire, receiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &lane.receiverPublicKey)
	if err := cvWriteUint32(&wire, len(leaf.coefficientCommitments)); err != nil {
		return nil, err
	}
	for i := range leaf.coefficientCommitments {
		if !cvValidG1(&leaf.coefficientCommitments[i], true) {
			return nil, fmt.Errorf("invalid APVSS coefficient commitment %d", i)
		}
		cvWritePoint(&wire, &leaf.coefficientCommitments[i])
	}
	cvWritePoint(&wire, &lane.encryptedShare.receiverPublicKey)
	cvWritePoint(&wire, &lane.encryptedShare.commitment)
	if err := cvWriteUint32(&wire, len(lane.encryptedShare.scalarChunks)); err != nil {
		return nil, err
	}
	for i := range lane.encryptedShare.scalarChunks {
		cvWriteCiphertext(&wire, &lane.encryptedShare.scalarChunks[i])
	}
	cvWriteCiphertext(&wire, &lane.encryptedShare.blinding)
	return wire.Bytes(), nil
}

func apvssLaneStatementDigestV1(leaf *cvLeafV1, receiverIndex int) ([]byte, error) {
	wire, err := apvssLaneStatementBytesV1(leaf, receiverIndex)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(apvssLaneStatementDomain), wire), nil
}

func apvssACKChallengeV1(
	statementDigest []byte,
	nonce *bls12381.G1Affine,
) (fr.Element, error) {
	if len(statementDigest) == 0 || !cvValidG1(nonce, false) {
		return fr.Element{}, fmt.Errorf("invalid APVSS ACK challenge input")
	}
	nonceWire := nonce.Bytes()
	return cvHashToFrV1(apvssACKChallengeDomain, statementDigest, nonceWire[:])
}

func apvssIssueLaneACKV1(
	context *cvLeafContextV1,
	leaf *cvLeafV1,
	receiverIndex int,
	receiverSecret fr.Element,
) (apvssLaneACKV1, error) {
	if err := apvssValidateStructuralLeafV1(context, leaf); err != nil {
		return apvssLaneACKV1{}, err
	}
	return apvssIssueVerifiedLaneACKV1(context, leaf, receiverIndex, receiverSecret)
}

func apvssIssueVerifiedLaneACKV1(
	context *cvLeafContextV1,
	leaf *cvLeafV1,
	receiverIndex int,
	receiverSecret fr.Element,
) (apvssLaneACKV1, error) {
	lane, err := apvssLaneV1(leaf, receiverIndex)
	if err != nil {
		return apvssLaneACKV1{}, err
	}
	if _, err := apvssDecryptLaneStrictV1(context.profile, receiverSecret, lane.encryptedShare); err != nil {
		return apvssLaneACKV1{}, err
	}
	statementDigest, err := apvssLaneStatementDigestV1(leaf, receiverIndex)
	if err != nil {
		return apvssLaneACKV1{}, err
	}

	var nonce fr.Element
	for nonce.IsZero() {
		if _, err := nonce.SetRandom(); err != nil {
			return apvssLaneACKV1{}, err
		}
	}
	var noncePoint bls12381.G1Affine
	noncePoint.ScalarMultiplication(&genG1, nonce.BigInt(new(big.Int)))
	challenge, err := apvssACKChallengeV1(statementDigest, &noncePoint)
	if err != nil {
		return apvssLaneACKV1{}, err
	}
	var response, term fr.Element
	term.Mul(&challenge, &receiverSecret)
	response.Add(&nonce, &term)
	return apvssLaneACKV1{
		receiverIndex: receiverIndex,
		signature: apvssSchnorrSignatureV1{
			r: noncePoint,
			z: response,
		},
	}, nil
}

func apvssVerifyLaneACKV1(leaf *cvLeafV1, ack *apvssLaneACKV1) error {
	if ack == nil || !cvValidG1(&ack.signature.r, false) {
		return fmt.Errorf("invalid APVSS ACK")
	}
	lane, err := apvssLaneV1(leaf, ack.receiverIndex)
	if err != nil {
		return err
	}
	statementDigest, err := apvssLaneStatementDigestV1(leaf, ack.receiverIndex)
	if err != nil {
		return err
	}
	challenge, err := apvssACKChallengeV1(statementDigest, &ack.signature.r)
	if err != nil {
		return err
	}
	var lhs, publicTerm, rhs bls12381.G1Affine
	lhs.ScalarMultiplication(&genG1, ack.signature.z.BigInt(new(big.Int)))
	publicTerm.ScalarMultiplication(&lane.receiverPublicKey, challenge.BigInt(new(big.Int)))
	rhs.Add(&ack.signature.r, &publicTerm)
	if !lhs.Equal(&rhs) {
		return fmt.Errorf("invalid APVSS receiver ACK signature")
	}
	return nil
}

func apvssFallbackLeafV1(
	leaf *cvLeafV1,
	receiverIndex int,
) (*cvLeafContextV1, *cvLeafV1, error) {
	lane, err := apvssLaneV1(leaf, receiverIndex)
	if err != nil {
		return nil, nil, err
	}
	statementDigest, err := apvssLaneStatementDigestV1(leaf, receiverIndex)
	if err != nil {
		return nil, nil, err
	}
	context := cvLeafContextV1{
		sessionID:          hashBytes([]byte(apvssFallbackDomain), statementDigest),
		epoch:              leaf.context.epoch,
		sharingDegree:      0,
		profile:            leaf.context.profile,
		receiverPublicKeys: []bls12381.G1Affine{lane.receiverPublicKey},
		dealerSetPolicy:    append([]byte(nil), statementDigest...),
		proofProfile:       cvLeafV1GrothProofProfile,
	}
	proxy := &cvLeafV1{
		context:                cvCloneLeafContextV1(context),
		dealerID:               leaf.dealerID,
		coefficientCommitments: []bls12381.G1Affine{lane.encryptedShare.commitment},
		receivers: []cvLeafReceiverV1{{
			receiverIndex:     1,
			receiverPublicKey: lane.receiverPublicKey,
			encryptedShare:    lane.encryptedShare,
		}},
		hasLeafNIZK: true,
	}
	return &context, proxy, nil
}

func apvssProveFallbackLaneV1(
	leaf *cvLeafV1,
	receiverIndex int,
	scalar, blinding fr.Element,
	scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (apvssFallbackProofV1, error) {
	_, proxy, err := apvssFallbackLeafV1(leaf, receiverIndex)
	if err != nil {
		return apvssFallbackProofV1{}, err
	}
	proof, err := cvProveLeafV1(
		proxy,
		[]fr.Element{scalar},
		[]fr.Element{blinding},
		scalarCoins,
		blindingCoin,
	)
	if err != nil {
		return apvssFallbackProofV1{}, err
	}
	proxy.proof = proof
	proxy.digest = cvLeafV1Digest(proxy)
	if proxy.digest == nil {
		return apvssFallbackProofV1{}, fmt.Errorf("encode APVSS fallback proof")
	}
	return apvssFallbackProofV1{receiverIndex: receiverIndex, proof: proof}, nil
}

func apvssVerifyFallbackLaneV1(leaf *cvLeafV1, fallback *apvssFallbackProofV1) error {
	if fallback == nil || fallback.proof == nil {
		return fmt.Errorf("missing APVSS fallback proof")
	}
	context, proxy, err := apvssFallbackLeafV1(leaf, fallback.receiverIndex)
	if err != nil {
		return err
	}
	proxy.proof = fallback.proof
	proxy.digest = cvLeafV1Digest(proxy)
	if proxy.digest == nil {
		return fmt.Errorf("encode APVSS fallback proof")
	}
	if err := cvVerifyLeafV1(context, proxy); err != nil {
		return fmt.Errorf("invalid APVSS fallback proof for receiver %d: %w", fallback.receiverIndex, err)
	}
	return nil
}

func apvssBuildPrototypeV1(
	context *cvLeafContextV1,
	leaf *cvLeafV1,
	receiverSecrets []fr.Element,
	witness *apvssDealerWitnessV1,
	fallbackIndices []int,
) (*apvssLeafPrototypeV1, error) {
	if err := apvssValidateStructuralLeafV1(context, leaf); err != nil {
		return nil, err
	}
	if witness == nil || len(receiverSecrets) != len(leaf.receivers) ||
		len(witness.scalars) != len(leaf.receivers) ||
		len(witness.blindings) != len(leaf.receivers) ||
		len(witness.scalarCoins) != len(leaf.receivers) ||
		len(witness.blindingCoins) != len(leaf.receivers) {
		return nil, fmt.Errorf("invalid APVSS dealer/receiver witness dimensions")
	}
	fallbackSet := make(map[int]struct{}, len(fallbackIndices))
	for i, receiverIndex := range fallbackIndices {
		if receiverIndex <= 0 || receiverIndex > len(leaf.receivers) ||
			(i > 0 && fallbackIndices[i-1] >= receiverIndex) {
			return nil, fmt.Errorf("APVSS fallback indices must be strictly ordered and in range")
		}
		fallbackSet[receiverIndex] = struct{}{}
	}
	if len(fallbackIndices) > context.sharingDegree {
		return nil, fmt.Errorf("APVSS fallback set exceeds f")
	}

	prototype := &apvssLeafPrototypeV1{leaf: leaf}
	for receiverIndex := 1; receiverIndex <= len(leaf.receivers); receiverIndex++ {
		if _, fallback := fallbackSet[receiverIndex]; fallback {
			proof, err := apvssProveFallbackLaneV1(
				leaf,
				receiverIndex,
				witness.scalars[receiverIndex-1],
				witness.blindings[receiverIndex-1],
				witness.scalarCoins[receiverIndex-1],
				witness.blindingCoins[receiverIndex-1],
			)
			if err != nil {
				return nil, err
			}
			prototype.fallbackProofs = append(prototype.fallbackProofs, proof)
			continue
		}
		ack, err := apvssIssueLaneACKV1(context, leaf, receiverIndex, receiverSecrets[receiverIndex-1])
		if err != nil {
			return nil, err
		}
		prototype.acks = append(prototype.acks, ack)
	}
	wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssAssemblePrototypeV1(
	context *cvLeafContextV1,
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	acks []apvssLaneACKV1,
) (*apvssLeafPrototypeV1, error) {
	if err := apvssValidateStructuralLeafV1(context, leaf); err != nil {
		return nil, err
	}
	return apvssAssembleVerifiedPrototypeV1(context, leaf, witness, acks)
}

func apvssAssembleVerifiedPrototypeV1(
	context *cvLeafContextV1,
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	acks []apvssLaneACKV1,
) (*apvssLeafPrototypeV1, error) {
	n := len(leaf.receivers)
	if witness == nil || len(witness.scalars) != n || len(witness.blindings) != n ||
		len(witness.scalarCoins) != n || len(witness.blindingCoins) != n {
		return nil, fmt.Errorf("invalid APVSS dealer witness dimensions")
	}
	ackSet := make(map[int]apvssLaneACKV1, len(acks))
	for i := range acks {
		ack := acks[i]
		if ack.receiverIndex <= 0 || ack.receiverIndex > n {
			return nil, fmt.Errorf("APVSS ACK receiver index outside roster")
		}
		if _, duplicate := ackSet[ack.receiverIndex]; duplicate {
			return nil, fmt.Errorf("duplicate APVSS ACK receiver index")
		}
		if err := apvssVerifyLaneACKV1(leaf, &ack); err != nil {
			return nil, err
		}
		ackSet[ack.receiverIndex] = ack
	}
	if len(ackSet) < n-context.sharingDegree {
		return nil, fmt.Errorf("APVSS ACK set is below n-f")
	}
	prototype := &apvssLeafPrototypeV1{leaf: leaf}
	for receiverIndex := 1; receiverIndex <= n; receiverIndex++ {
		if ack, ok := ackSet[receiverIndex]; ok {
			prototype.acks = append(prototype.acks, ack)
			continue
		}
		fallback, err := apvssProveFallbackLaneV1(
			leaf,
			receiverIndex,
			witness.scalars[receiverIndex-1],
			witness.blindings[receiverIndex-1],
			witness.scalarCoins[receiverIndex-1],
			witness.blindingCoins[receiverIndex-1],
		)
		if err != nil {
			return nil, err
		}
		prototype.fallbackProofs = append(prototype.fallbackProofs, fallback)
	}
	wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssVerifyPrototypeV1(context *cvLeafContextV1, prototype *apvssLeafPrototypeV1) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	if err := apvssValidateStructuralLeafV1(context, prototype.leaf); err != nil {
		return err
	}
	return apvssVerifyPrototypePartitionV1(prototype)
}

func apvssVerifyPrototypePartitionV1(prototype *apvssLeafPrototypeV1) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	n := len(prototype.leaf.receivers)
	if len(prototype.fallbackProofs) > prototype.leaf.context.sharingDegree ||
		len(prototype.acks)+len(prototype.fallbackProofs) != n {
		return fmt.Errorf("APVSS ACK and fallback sets do not cover receivers exactly")
	}
	covered := make([]bool, n)
	previous := 0
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		if ack.receiverIndex <= previous || ack.receiverIndex <= 0 || ack.receiverIndex > n ||
			covered[ack.receiverIndex-1] {
			return fmt.Errorf("APVSS ACK indices are not a strict set")
		}
		if err := apvssVerifyLaneACKV1(prototype.leaf, ack); err != nil {
			return err
		}
		covered[ack.receiverIndex-1] = true
		previous = ack.receiverIndex
	}
	previous = 0
	for i := range prototype.fallbackProofs {
		fallback := &prototype.fallbackProofs[i]
		if fallback.receiverIndex <= previous || fallback.receiverIndex <= 0 || fallback.receiverIndex > n ||
			covered[fallback.receiverIndex-1] {
			return fmt.Errorf("APVSS fallback indices are not the ACK complement")
		}
		if err := apvssVerifyFallbackLaneV1(prototype.leaf, fallback); err != nil {
			return err
		}
		covered[fallback.receiverIndex-1] = true
		previous = fallback.receiverIndex
	}
	for receiver, ok := range covered {
		if !ok {
			return fmt.Errorf("APVSS receiver %d is absent from ACK and fallback sets", receiver+1)
		}
	}
	return nil
}

func apvssProofMaterialBytesV1(prototype *apvssLeafPrototypeV1) (int, error) {
	if prototype == nil {
		return 0, fmt.Errorf("nil APVSS prototype")
	}
	// receiver index + compressed nonce + scalar response
	total := len(prototype.acks) * (4 + bls12381.SizeOfG1AffineCompressed + fr.Bytes)
	for i := range prototype.fallbackProofs {
		wire, err := cvLeafProofV1CanonicalBytes(prototype.fallbackProofs[i].proof)
		if err != nil {
			return 0, err
		}
		total += 4 + len(wire)
	}
	return total, nil
}
