package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssLaneStatementDomain = "ARL-APVSS/lane-statement"
	apvssACKChallengeDomain  = "ARL-APVSS/receiver-ack"
	apvssFallbackDomain      = "ARL-APVSS/exact-lane-fallback"
	apvssLeafDigestDomain    = "ARL-APVSS/leaf"
	apvssLeafWireDomain      = "ARL-APVSS/leaf-wire"
	apvssACKMessageDomain    = "ARL-APVSS/ack-message"
	apvssFallbackSetDomain   = "ARL-APVSS/fallback-set"

	apvssFallbackExactLaneProfile    = "exact-lane"
	apvssFallbackCompactBatchProfile = "compact-batch"
	apvssFallbackProfileMarker       = 0x41505631
)

type apvssSchnorrSignature struct {
	r bls12381.G1Affine
	z fr.Element
}

type apvssLaneACK struct {
	receiverIndex int
	signature     apvssSchnorrSignature
}

type apvssFallbackProof struct {
	receiverIndex int
	proof         *cvLeafProof
}

// apvssLeafPrototype deliberately wraps a structural CV leaf. Every wire
// explicitly binds the exact-lane or compact-batch fallback profile.
type apvssLeafPrototype struct {
	leaf            *cvLeaf
	acks            []apvssLaneACK
	fallbackProfile string
	fallbackProofs  []apvssFallbackProof
	fallbackIndices []int
	compactFallback *apvssCompactFallbackProof
	digest          []byte
}

type apvssLaneACKMessage struct {
	dealerID   uint64
	leafDigest []byte
	ack        apvssLaneACK
}

type apvssDealerWitness struct {
	scalars       []fr.Element
	blindings     []fr.Element
	scalarCoins   [][]fr.Element
	blindingCoins []fr.Element
}

func apvssNormalizeFallbackProfile(profile string) string {
	return profile
}

func apvssRequireFallbackBackend(profile string) error {
	switch apvssNormalizeFallbackProfile(profile) {
	case apvssFallbackExactLaneProfile:
		return nil
	case apvssFallbackCompactBatchProfile:
		return nil
	default:
		return fmt.Errorf("unsupported APVSS fallback proof profile %q", profile)
	}
}

func apvssPrototypeFallbackIndices(prototype *apvssLeafPrototype) ([]int, error) {
	if prototype == nil {
		return nil, fmt.Errorf("nil APVSS prototype")
	}
	switch apvssNormalizeFallbackProfile(prototype.fallbackProfile) {
	case apvssFallbackExactLaneProfile:
		if len(prototype.fallbackIndices) != 0 || prototype.compactFallback != nil {
			return nil, fmt.Errorf("exact APVSS fallback carries compact proof fields")
		}
		indices := make([]int, len(prototype.fallbackProofs))
		for i := range prototype.fallbackProofs {
			indices[i] = prototype.fallbackProofs[i].receiverIndex
		}
		return indices, nil
	case apvssFallbackCompactBatchProfile:
		if len(prototype.fallbackProofs) != 0 {
			return nil, fmt.Errorf("compact APVSS fallback carries exact proofs")
		}
		indices := append([]int(nil), prototype.fallbackIndices...)
		if len(indices) == 0 {
			if prototype.compactFallback != nil {
				return nil, fmt.Errorf("empty compact APVSS fallback set carries a proof")
			}
			return indices, nil
		}
		if prototype.compactFallback == nil || prototype.compactFallback.link == nil {
			return nil, fmt.Errorf("missing compact APVSS fallback proof")
		}
		proofIndices := apvssCompactLinkReceiverIndices(prototype.compactFallback.link)
		if len(proofIndices) != len(indices) {
			return nil, fmt.Errorf("compact APVSS fallback proof set mismatch")
		}
		for i := range indices {
			if indices[i] != proofIndices[i] {
				return nil, fmt.Errorf("compact APVSS fallback proof order mismatch")
			}
		}
		return indices, nil
	default:
		return nil, fmt.Errorf("unsupported APVSS fallback proof profile %q", prototype.fallbackProfile)
	}
}

func apvssPrototypeFallbackCount(prototype *apvssLeafPrototype) int {
	indices, err := apvssPrototypeFallbackIndices(prototype)
	if err != nil {
		return 0
	}
	return len(indices)
}

func apvssRequireProductionFallbackBackend(profile string) error {
	switch apvssNormalizeFallbackProfile(profile) {
	case apvssFallbackExactLaneProfile:
		return fmt.Errorf("APVSS exact-lane fallback lacks a public canonical <q comparator")
	case apvssFallbackCompactBatchProfile:
		return fmt.Errorf("APVSS compact batch fallback is experimental pending independent cryptographic review")
	default:
		return fmt.Errorf("unsupported APVSS fallback proof profile %q", profile)
	}
}

// apvssFallbackSetStatementDigest freezes the joint statement a future
// compact backend must prove. The digest binds the ordered I set and every
// complete lane statement; it does not weaken the current exact verifier.
func apvssFallbackSetStatementDigest(
	leaf *cvLeaf,
	receiverIndices []int,
	profile string,
) ([]byte, error) {
	normalizedProfile := apvssNormalizeFallbackProfile(profile)
	switch normalizedProfile {
	case apvssFallbackExactLaneProfile, apvssFallbackCompactBatchProfile:
	default:
		return nil, fmt.Errorf("unsupported APVSS fallback proof profile %q", profile)
	}
	if leaf == nil || len(receiverIndices) > leaf.context.sharingDegree {
		return nil, fmt.Errorf("invalid APVSS fallback statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssFallbackSetDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, []byte(normalizedProfile)); err != nil {
		return nil, err
	}
	contextDigest := cvLeafContextDigest(&leaf.context)
	if len(contextDigest) == 0 {
		return nil, fmt.Errorf("encode APVSS fallback context")
	}
	if err := cvWriteBytes(&wire, contextDigest); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, leaf.dealerID)
	if err := cvWriteUint32(&wire, len(receiverIndices)); err != nil {
		return nil, err
	}
	previous := 0
	for _, receiverIndex := range receiverIndices {
		if receiverIndex <= previous || receiverIndex <= 0 || receiverIndex > len(leaf.receivers) {
			return nil, fmt.Errorf("APVSS fallback indices must be strictly ordered and in range")
		}
		statementDigest, err := apvssLaneStatementDigest(leaf, receiverIndex)
		if err != nil {
			return nil, err
		}
		if err := cvWriteUint32(&wire, receiverIndex); err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, statementDigest); err != nil {
			return nil, err
		}
		previous = receiverIndex
	}
	return hashBytes([]byte(apvssFallbackSetDomain), wire.Bytes()), nil
}

func apvssValidateStructuralLeaf(context *cvLeafContext, leaf *cvLeaf) error {
	if context == nil || context.proofProfile != cvLeafStructuralProofProfile {
		return fmt.Errorf("APVSS base leaf must use the structural proof profile")
	}
	return cvVerifyLeaf(context, leaf)
}

func apvssLane(leaf *cvLeaf, receiverIndex int) (*cvLeafReceiver, error) {
	if leaf == nil || receiverIndex <= 0 || receiverIndex > len(leaf.receivers) {
		return nil, fmt.Errorf("APVSS receiver index outside leaf")
	}
	lane := &leaf.receivers[receiverIndex-1]
	if lane.receiverIndex != receiverIndex {
		return nil, fmt.Errorf("APVSS receiver lane index mismatch")
	}
	return lane, nil
}

// apvssDecryptLaneStrict differs from cvDecryptShare in one security-critical
// respect: it rejects a reconstructed integer outside [0,q), rather than
// reducing it modulo q. ACKs must only be issued for canonical digit encodings.
func apvssDecryptLaneStrict(
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

func apvssLaneStatementBytes(leaf *cvLeaf, receiverIndex int) ([]byte, error) {
	lane, err := apvssLane(leaf, receiverIndex)
	if err != nil {
		return nil, err
	}
	if err := cvValidateLeafContext(&leaf.context); err != nil {
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
	expectedCommitment := cvEvaluateCommitments(leaf.coefficientCommitments, receiverIndex)
	if !lane.encryptedShare.commitment.Equal(&expectedCommitment) {
		return nil, fmt.Errorf("APVSS lane commitment is not the polynomial evaluation")
	}
	contextDigest := cvLeafContextDigest(&leaf.context)
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

func apvssLaneStatementDigest(leaf *cvLeaf, receiverIndex int) ([]byte, error) {
	wire, err := apvssLaneStatementBytes(leaf, receiverIndex)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(apvssLaneStatementDomain), wire), nil
}

func apvssACKChallenge(
	statementDigest []byte,
	nonce *bls12381.G1Affine,
) (fr.Element, error) {
	if len(statementDigest) == 0 || !cvValidG1(nonce, false) {
		return fr.Element{}, fmt.Errorf("invalid APVSS ACK challenge input")
	}
	nonceWire := nonce.Bytes()
	return cvHashToFr(apvssACKChallengeDomain, statementDigest, nonceWire[:])
}

func apvssIssueLaneACK(
	context *cvLeafContext,
	leaf *cvLeaf,
	receiverIndex int,
	receiverSecret fr.Element,
) (apvssLaneACK, error) {
	if err := apvssValidateStructuralLeaf(context, leaf); err != nil {
		return apvssLaneACK{}, err
	}
	return apvssIssueVerifiedLaneACK(context, leaf, receiverIndex, receiverSecret)
}

func apvssIssueVerifiedLaneACK(
	context *cvLeafContext,
	leaf *cvLeaf,
	receiverIndex int,
	receiverSecret fr.Element,
) (apvssLaneACK, error) {
	lane, err := apvssLane(leaf, receiverIndex)
	if err != nil {
		return apvssLaneACK{}, err
	}
	if _, err := apvssDecryptLaneStrict(context.profile, receiverSecret, lane.encryptedShare); err != nil {
		return apvssLaneACK{}, err
	}
	statementDigest, err := apvssLaneStatementDigest(leaf, receiverIndex)
	if err != nil {
		return apvssLaneACK{}, err
	}

	var nonce fr.Element
	for nonce.IsZero() {
		if _, err := nonce.SetRandom(); err != nil {
			return apvssLaneACK{}, err
		}
	}
	var noncePoint bls12381.G1Affine
	noncePoint.ScalarMultiplication(&genG1, nonce.BigInt(new(big.Int)))
	challenge, err := apvssACKChallenge(statementDigest, &noncePoint)
	if err != nil {
		return apvssLaneACK{}, err
	}
	var response, term fr.Element
	term.Mul(&challenge, &receiverSecret)
	response.Add(&nonce, &term)
	return apvssLaneACK{
		receiverIndex: receiverIndex,
		signature: apvssSchnorrSignature{
			r: noncePoint,
			z: response,
		},
	}, nil
}

func apvssVerifyLaneACK(leaf *cvLeaf, ack *apvssLaneACK) error {
	if ack == nil || !cvValidG1(&ack.signature.r, false) {
		return fmt.Errorf("invalid APVSS ACK")
	}
	lane, err := apvssLane(leaf, ack.receiverIndex)
	if err != nil {
		return err
	}
	statementDigest, err := apvssLaneStatementDigest(leaf, ack.receiverIndex)
	if err != nil {
		return err
	}
	challenge, err := apvssACKChallenge(statementDigest, &ack.signature.r)
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

func apvssFallbackLeaf(
	leaf *cvLeaf,
	receiverIndex int,
) (*cvLeafContext, *cvLeaf, error) {
	lane, err := apvssLane(leaf, receiverIndex)
	if err != nil {
		return nil, nil, err
	}
	statementDigest, err := apvssLaneStatementDigest(leaf, receiverIndex)
	if err != nil {
		return nil, nil, err
	}
	context := cvLeafContext{
		sessionID:          hashBytes([]byte(apvssFallbackDomain), statementDigest),
		epoch:              leaf.context.epoch,
		sharingDegree:      0,
		profile:            leaf.context.profile,
		receiverPublicKeys: []bls12381.G1Affine{lane.receiverPublicKey},
		dealerSetPolicy:    append([]byte(nil), statementDigest...),
		proofProfile:       cvLeafGrothProofProfile,
	}
	proxy := &cvLeaf{
		context:                cvCloneLeafContext(context),
		dealerID:               leaf.dealerID,
		coefficientCommitments: []bls12381.G1Affine{lane.encryptedShare.commitment},
		receivers: []cvLeafReceiver{{
			receiverIndex:     1,
			receiverPublicKey: lane.receiverPublicKey,
			encryptedShare:    lane.encryptedShare,
		}},
		hasLeafNIZK: true,
	}
	return &context, proxy, nil
}

func apvssEqualCiphertext(left, right *cvElGamalCiphertext) bool {
	return left != nil && right != nil && left.r.Equal(&right.r) && left.c.Equal(&right.c)
}

// apvssValidateFallbackLaneWitness is the reference conformance gate for a
// future compact prover. Re-encryption from a canonical fr scalar enforces
// digit range/radix reconstruction, ciphertext plaintext and randomness links,
// and the same rho in the blinding ciphertext and Pedersen evaluation. The
// current exact prover already proves these equations and does not repeat this
// relatively expensive check on its hot path.
func apvssValidateFallbackLaneWitness(
	leaf *cvLeaf,
	receiverIndex int,
	scalar, blinding fr.Element,
	scalarCoins []fr.Element,
	blindingCoin fr.Element,
) error {
	lane, err := apvssLane(leaf, receiverIndex)
	if err != nil {
		return err
	}
	expected, err := cvReferenceEncryptShare(
		leaf.context.profile,
		lane.receiverPublicKey,
		scalar,
		blinding,
		scalarCoins,
		blindingCoin,
	)
	if err != nil {
		return err
	}
	actual := lane.encryptedShare
	if actual == nil || !actual.receiverPublicKey.Equal(&expected.receiverPublicKey) ||
		!actual.commitment.Equal(&expected.commitment) ||
		len(actual.scalarChunks) != len(expected.scalarChunks) ||
		!apvssEqualCiphertext(&actual.blinding, &expected.blinding) {
		return fmt.Errorf("APVSS fallback witness does not open receiver %d lane", receiverIndex)
	}
	for chunk := range actual.scalarChunks {
		if !apvssEqualCiphertext(&actual.scalarChunks[chunk], &expected.scalarChunks[chunk]) {
			return fmt.Errorf(
				"APVSS fallback witness does not open receiver %d scalar chunk %d",
				receiverIndex,
				chunk,
			)
		}
	}
	return nil
}

func apvssProveFallbackLane(
	leaf *cvLeaf,
	receiverIndex int,
	scalar, blinding fr.Element,
	scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (apvssFallbackProof, error) {
	_, proxy, err := apvssFallbackLeaf(leaf, receiverIndex)
	if err != nil {
		return apvssFallbackProof{}, err
	}
	proof, err := cvProveLeaf(
		proxy,
		[]fr.Element{scalar},
		[]fr.Element{blinding},
		scalarCoins,
		blindingCoin,
	)
	if err != nil {
		return apvssFallbackProof{}, err
	}
	proxy.proof = proof
	proxy.digest = cvLeafDigest(proxy)
	if proxy.digest == nil {
		return apvssFallbackProof{}, fmt.Errorf("encode APVSS fallback proof")
	}
	return apvssFallbackProof{receiverIndex: receiverIndex, proof: proof}, nil
}

func apvssVerifyFallbackLane(leaf *cvLeaf, fallback *apvssFallbackProof) error {
	if fallback == nil || fallback.proof == nil {
		return fmt.Errorf("missing APVSS fallback proof")
	}
	context, proxy, err := apvssFallbackLeaf(leaf, fallback.receiverIndex)
	if err != nil {
		return err
	}
	proxy.proof = fallback.proof
	proxy.digest = cvLeafDigest(proxy)
	if proxy.digest == nil {
		return fmt.Errorf("encode APVSS fallback proof")
	}
	if err := cvVerifyLeaf(context, proxy); err != nil {
		return fmt.Errorf("invalid APVSS fallback proof for receiver %d: %w", fallback.receiverIndex, err)
	}
	return nil
}

func apvssBuildPrototype(
	context *cvLeafContext,
	leaf *cvLeaf,
	receiverSecrets []fr.Element,
	witness *apvssDealerWitness,
	fallbackIndices []int,
) (*apvssLeafPrototype, error) {
	return apvssBuildPrototypeWithFallbackProfile(
		context,
		leaf,
		receiverSecrets,
		witness,
		fallbackIndices,
		apvssFallbackExactLaneProfile,
	)
}

func apvssBuildPrototypeWithFallbackProfile(
	context *cvLeafContext,
	leaf *cvLeaf,
	receiverSecrets []fr.Element,
	witness *apvssDealerWitness,
	fallbackIndices []int,
	fallbackProfile string,
) (*apvssLeafPrototype, error) {
	if err := apvssValidateStructuralLeaf(context, leaf); err != nil {
		return nil, err
	}
	if err := apvssRequireFallbackBackend(fallbackProfile); err != nil {
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
	if _, err := apvssFallbackSetStatementDigest(leaf, fallbackIndices, fallbackProfile); err != nil {
		return nil, err
	}

	prototype := &apvssLeafPrototype{
		leaf:            leaf,
		fallbackProfile: apvssNormalizeFallbackProfile(fallbackProfile),
	}
	for receiverIndex := 1; receiverIndex <= len(leaf.receivers); receiverIndex++ {
		if _, fallback := fallbackSet[receiverIndex]; fallback {
			if prototype.fallbackProfile == apvssFallbackExactLaneProfile {
				proof, err := apvssProveFallbackLane(
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
			} else {
				prototype.fallbackIndices = append(prototype.fallbackIndices, receiverIndex)
			}
			continue
		}
		ack, err := apvssIssueLaneACK(context, leaf, receiverIndex, receiverSecrets[receiverIndex-1])
		if err != nil {
			return nil, err
		}
		prototype.acks = append(prototype.acks, ack)
	}
	if prototype.fallbackProfile == apvssFallbackCompactBatchProfile && len(fallbackIndices) > 0 {
		proof, err := apvssProveCompactFallback(leaf, witness, fallbackIndices)
		if err != nil {
			return nil, err
		}
		prototype.compactFallback = proof
	}
	wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssAssemblePrototype(
	context *cvLeafContext,
	leaf *cvLeaf,
	witness *apvssDealerWitness,
	acks []apvssLaneACK,
) (*apvssLeafPrototype, error) {
	if err := apvssValidateStructuralLeaf(context, leaf); err != nil {
		return nil, err
	}
	return apvssAssembleVerifiedPrototype(context, leaf, witness, acks)
}

func apvssAssembleVerifiedPrototype(
	context *cvLeafContext,
	leaf *cvLeaf,
	witness *apvssDealerWitness,
	acks []apvssLaneACK,
) (*apvssLeafPrototype, error) {
	return apvssAssembleVerifiedPrototypeWithFallbackProfile(
		context, leaf, witness, acks, apvssFallbackExactLaneProfile,
	)
}

func apvssAssembleVerifiedPrototypeWithFallbackProfile(
	context *cvLeafContext,
	leaf *cvLeaf,
	witness *apvssDealerWitness,
	acks []apvssLaneACK,
	fallbackProfile string,
) (*apvssLeafPrototype, error) {
	n := len(leaf.receivers)
	if err := apvssRequireFallbackBackend(fallbackProfile); err != nil {
		return nil, err
	}
	if witness == nil || len(witness.scalars) != n || len(witness.blindings) != n ||
		len(witness.scalarCoins) != n || len(witness.blindingCoins) != n {
		return nil, fmt.Errorf("invalid APVSS dealer witness dimensions")
	}
	ackSet := make(map[int]apvssLaneACK, len(acks))
	for i := range acks {
		ack := acks[i]
		if ack.receiverIndex <= 0 || ack.receiverIndex > n {
			return nil, fmt.Errorf("APVSS ACK receiver index outside roster")
		}
		if _, duplicate := ackSet[ack.receiverIndex]; duplicate {
			return nil, fmt.Errorf("duplicate APVSS ACK receiver index")
		}
		if err := apvssVerifyLaneACK(leaf, &ack); err != nil {
			return nil, err
		}
		ackSet[ack.receiverIndex] = ack
	}
	if len(ackSet) < n-context.sharingDegree {
		return nil, fmt.Errorf("APVSS ACK set is below n_n-f_n")
	}
	prototype := &apvssLeafPrototype{
		leaf:            leaf,
		fallbackProfile: apvssNormalizeFallbackProfile(fallbackProfile),
	}
	for receiverIndex := 1; receiverIndex <= n; receiverIndex++ {
		if ack, ok := ackSet[receiverIndex]; ok {
			prototype.acks = append(prototype.acks, ack)
			continue
		}
		if prototype.fallbackProfile == apvssFallbackExactLaneProfile {
			fallback, err := apvssProveFallbackLane(
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
		} else {
			prototype.fallbackIndices = append(prototype.fallbackIndices, receiverIndex)
		}
	}
	if prototype.fallbackProfile == apvssFallbackCompactBatchProfile && len(prototype.fallbackIndices) > 0 {
		proof, err := apvssProveCompactFallback(leaf, witness, prototype.fallbackIndices)
		if err != nil {
			return nil, err
		}
		prototype.compactFallback = proof
	}
	wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssVerifyPrototype(context *cvLeafContext, prototype *apvssLeafPrototype) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	if err := apvssValidateStructuralLeaf(context, prototype.leaf); err != nil {
		return err
	}
	return apvssVerifyPrototypePartition(prototype)
}

func apvssVerifyPrototypePartition(prototype *apvssLeafPrototype) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	n := len(prototype.leaf.receivers)
	if err := apvssRequireFallbackBackend(prototype.fallbackProfile); err != nil {
		return err
	}
	fallbackIndices, err := apvssPrototypeFallbackIndices(prototype)
	if err != nil {
		return err
	}
	if len(fallbackIndices) > prototype.leaf.context.sharingDegree ||
		len(prototype.acks)+len(fallbackIndices) != n {
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
		if err := apvssVerifyLaneACK(prototype.leaf, ack); err != nil {
			return err
		}
		covered[ack.receiverIndex-1] = true
		previous = ack.receiverIndex
	}
	previous = 0
	for i, receiverIndex := range fallbackIndices {
		if receiverIndex <= previous || receiverIndex <= 0 || receiverIndex > n ||
			covered[receiverIndex-1] {
			return fmt.Errorf("APVSS fallback indices are not the ACK complement")
		}
		if apvssNormalizeFallbackProfile(prototype.fallbackProfile) == apvssFallbackExactLaneProfile {
			if err := apvssVerifyFallbackLane(prototype.leaf, &prototype.fallbackProofs[i]); err != nil {
				return err
			}
		}
		covered[receiverIndex-1] = true
		previous = receiverIndex
	}
	if _, err := apvssFallbackSetStatementDigest(
		prototype.leaf,
		fallbackIndices,
		prototype.fallbackProfile,
	); err != nil {
		return err
	}
	if apvssNormalizeFallbackProfile(prototype.fallbackProfile) == apvssFallbackCompactBatchProfile &&
		len(fallbackIndices) > 0 {
		if err := apvssVerifyCompactFallback(prototype.leaf, prototype.compactFallback); err != nil {
			return err
		}
	}
	for receiver, ok := range covered {
		if !ok {
			return fmt.Errorf("APVSS receiver %d is absent from ACK and fallback sets", receiver+1)
		}
	}
	return nil
}

func apvssProofMaterialBytes(prototype *apvssLeafPrototype) (int, error) {
	if prototype == nil {
		return 0, fmt.Errorf("nil APVSS prototype")
	}
	if _, err := apvssPrototypeFallbackIndices(prototype); err != nil {
		return 0, err
	}
	// receiver index + compressed nonce + scalar response
	total := len(prototype.acks) * (4 + bls12381.SizeOfG1AffineCompressed + fr.Bytes)
	for i := range prototype.fallbackProofs {
		wire, err := cvLeafProofCanonicalBytes(prototype.fallbackProofs[i].proof)
		if err != nil {
			return 0, err
		}
		total += 4 + len(wire)
	}
	if prototype.compactFallback != nil {
		wire, err := apvssCompactFallbackProofCanonicalBytes(prototype.leaf, prototype.compactFallback)
		if err != nil {
			return 0, err
		}
		total += 4*len(prototype.fallbackIndices) + len(wire)
	}
	return total, nil
}
