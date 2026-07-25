package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssCompactFallbackDomain            = "ARL-APVSS/compact-fallback"
	apvssCompactComparatorStatementDomain = "ARL-APVSS/canonical-comparator/statement"
	apvssCompactComparatorWeightDomain    = "ARL-APVSS/canonical-comparator/weight"
	apvssCompactComparatorChallengeDomain = "ARL-APVSS/canonical-comparator/challenge"
)

type apvssCompactComparatorProof struct {
	complementCommitments []bls12381.G1Affine
	borrowCommitments     []bls12381.G1Affine
	complementRange       *apvssCompactRangeProof
	borrowRange           *apvssCompactRangeProof
	tRelation             bls12381.G1Affine
	zRelation             fr.Element
}

type apvssCompactFallbackProof struct {
	link       *apvssCompactLinkProof
	digitRange *apvssCompactRangeProof
	comparator *apvssCompactComparatorProof
}

func apvssCompactLinkCommitments(proof *apvssCompactLinkProof) []bls12381.G1Affine {
	if proof == nil {
		return nil
	}
	var commitments []bls12381.G1Affine
	for laneIndex := range proof.lanes {
		for digitIndex := range proof.lanes[laneIndex].digits {
			commitments = append(commitments, proof.lanes[laneIndex].digits[digitIndex].commitment)
		}
	}
	return commitments
}

func apvssCompactModulusDigits(count int) ([]uint64, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid APVSS comparator digit count")
	}
	modulusMinusOne := new(big.Int).Sub(new(big.Int).Set(fr.Modulus()), big.NewInt(1))
	if modulusMinusOne.BitLen() > count*8 {
		return nil, fmt.Errorf("APVSS comparator radix is too short for scalar modulus")
	}
	encoded := modulusMinusOne.FillBytes(make([]byte, count))
	digits := make([]uint64, count)
	for i := 0; i < count; i++ {
		digits[i] = uint64(encoded[count-1-i])
	}
	return digits, nil
}

func apvssCompactComplementDigits(scalar fr.Element, count int) ([]uint64, error) {
	value := scalar.BigInt(new(big.Int))
	complement := new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Set(fr.Modulus()), big.NewInt(1)), value)
	if complement.Sign() < 0 {
		return nil, fmt.Errorf("APVSS comparator received a non-canonical scalar")
	}
	if complement.BitLen() > count*8 {
		return nil, fmt.Errorf("APVSS comparator complement exceeds radix")
	}
	encoded := complement.FillBytes(make([]byte, count))
	digits := make([]uint64, count)
	for i := 0; i < count; i++ {
		digits[i] = uint64(encoded[count-1-i])
	}
	return digits, nil
}

func apvssCompactComparatorBorrows(
	modulusDigits, scalarDigits, complementDigits []uint64,
) ([]uint64, error) {
	if len(modulusDigits) == 0 || len(modulusDigits) != len(scalarDigits) ||
		len(scalarDigits) != len(complementDigits) {
		return nil, fmt.Errorf("invalid APVSS comparator digit vectors")
	}
	borrows := make([]uint64, len(scalarDigits)-1)
	borrow := int64(0)
	for i := range scalarDigits {
		value := int64(modulusDigits[i]) - int64(scalarDigits[i]) - borrow
		nextBorrow := int64(0)
		if value < 0 {
			value += 256
			nextBorrow = 1
		}
		if uint64(value) != complementDigits[i] {
			return nil, fmt.Errorf("APVSS comparator complement mismatch at digit %d", i)
		}
		if i+1 < len(scalarDigits) {
			borrows[i] = uint64(nextBorrow)
		} else if nextBorrow != 0 {
			return nil, fmt.Errorf("APVSS comparator final borrow is nonzero")
		}
		borrow = nextBorrow
	}
	return borrows, nil
}

func apvssCompactComparatorStatement(
	leaf *cvLeaf,
	link *apvssCompactLinkProof,
	proof *apvssCompactComparatorProof,
) ([]byte, error) {
	if leaf == nil || link == nil || proof == nil {
		return nil, fmt.Errorf("invalid APVSS comparator statement")
	}
	fallbackDigest, err := apvssFallbackSetStatementDigest(
		leaf,
		apvssCompactLinkReceiverIndices(link),
		apvssFallbackCompactBatchProfile,
	)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssCompactComparatorStatementDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, fallbackDigest); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, apvssCompactLinkCommitments(link)); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.complementCommitments); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.borrowCommitments); err != nil {
		return nil, err
	}
	return hashBytes([]byte(apvssCompactComparatorStatementDomain), wire.Bytes()), nil
}

func apvssCompactSubproofStatement(statement []byte, label string) []byte {
	return hashBytes([]byte(apvssCompactFallbackDomain+"/"+label), statement)
}

func apvssCompactComparatorAggregate(
	statement []byte,
	link *apvssCompactLinkProof,
	proof *apvssCompactComparatorProof,
	modulusDigits []uint64,
	withBlindings bool,
	scalarBlindings, complementBlindings, borrowBlindings []fr.Element,
) (bls12381.G1Affine, fr.Element, error) {
	weight, err := apvssCompactChallenge(apvssCompactComparatorWeightDomain, statement)
	if err != nil {
		return bls12381.G1Affine{}, fr.Element{}, err
	}
	weights := apvssCompactScalarPowers(weight, len(proof.complementCommitments))
	scalarCommitments := apvssCompactLinkCommitments(link)
	chunks := len(modulusDigits)
	lanes := len(link.lanes)
	if len(scalarCommitments) != lanes*chunks || len(proof.complementCommitments) != lanes*chunks ||
		len(proof.borrowCommitments) != lanes*(chunks-1) {
		return bls12381.G1Affine{}, fr.Element{}, fmt.Errorf("invalid APVSS comparator equation shape")
	}
	scalarCoefficients := make([]fr.Element, len(scalarCommitments))
	complementCoefficients := make([]fr.Element, len(proof.complementCommitments))
	borrowCoefficients := make([]fr.Element, len(proof.borrowCommitments))
	var generatorCoefficient, radix fr.Element
	radix.SetUint64(256)
	for lane := 0; lane < lanes; lane++ {
		for digit := 0; digit < chunks; digit++ {
			index := lane*chunks + digit
			scalarCoefficients[index].Neg(&weights[index])
			complementCoefficients[index].Neg(&weights[index])
			var modulusScalar, term fr.Element
			modulusScalar.SetUint64(modulusDigits[digit])
			term.Mul(&weights[index], &modulusScalar)
			generatorCoefficient.Add(&generatorCoefficient, &term)
			if digit > 0 {
				borrowIndex := lane*(chunks-1) + digit - 1
				term.Neg(&weights[index])
				borrowCoefficients[borrowIndex].Add(&borrowCoefficients[borrowIndex], &term)
			}
			if digit+1 < chunks {
				borrowIndex := lane*(chunks-1) + digit
				term.Mul(&weights[index], &radix)
				borrowCoefficients[borrowIndex].Add(&borrowCoefficients[borrowIndex], &term)
			}
		}
	}
	points := make([]bls12381.G1Affine, 0, len(scalarCommitments)+len(proof.complementCommitments)+len(proof.borrowCommitments)+1)
	coefficients := make([]fr.Element, 0, cap(points))
	points = append(points, scalarCommitments...)
	coefficients = append(coefficients, scalarCoefficients...)
	points = append(points, proof.complementCommitments...)
	coefficients = append(coefficients, complementCoefficients...)
	points = append(points, proof.borrowCommitments...)
	coefficients = append(coefficients, borrowCoefficients...)
	points = append(points, genG1)
	coefficients = append(coefficients, generatorCoefficient)
	aggregate := apvssCompactPointSum(points, coefficients)
	var aggregateBlinding fr.Element
	if withBlindings {
		for i := range scalarBlindings {
			var term fr.Element
			term.Mul(&scalarCoefficients[i], &scalarBlindings[i])
			aggregateBlinding.Add(&aggregateBlinding, &term)
			term.Mul(&complementCoefficients[i], &complementBlindings[i])
			aggregateBlinding.Add(&aggregateBlinding, &term)
		}
		for i := range borrowBlindings {
			var term fr.Element
			term.Mul(&borrowCoefficients[i], &borrowBlindings[i])
			aggregateBlinding.Add(&aggregateBlinding, &term)
		}
	}
	return aggregate, aggregateBlinding, nil
}

func apvssProveCompactComparator(
	leaf *cvLeaf,
	witness *apvssDealerWitness,
	link *apvssCompactLinkProof,
	scalarDigits []uint64,
	scalarBlindings []fr.Element,
) (*apvssCompactComparatorProof, error) {
	if leaf == nil || witness == nil || link == nil || len(link.lanes) == 0 {
		return nil, fmt.Errorf("invalid APVSS compact comparator witness")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	if len(scalarDigits) != len(link.lanes)*chunks || len(scalarBlindings) != len(scalarDigits) {
		return nil, fmt.Errorf("invalid APVSS compact comparator digit openings")
	}
	modulusDigits, err := apvssCompactModulusDigits(chunks)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactComparatorProof{
		complementCommitments: make([]bls12381.G1Affine, 0, len(scalarDigits)),
		borrowCommitments:     make([]bls12381.G1Affine, 0, len(link.lanes)*(chunks-1)),
	}
	complementValues := make([]uint64, 0, len(scalarDigits))
	complementBlindings := make([]fr.Element, 0, len(scalarDigits))
	borrowValues := make([]uint64, 0, len(link.lanes)*(chunks-1))
	borrowBlindings := make([]fr.Element, 0, len(link.lanes)*(chunks-1))
	for laneIndex, lane := range link.lanes {
		witnessIndex := lane.receiverIndex - 1
		complements, err := apvssCompactComplementDigits(witness.scalars[witnessIndex], chunks)
		if err != nil {
			return nil, err
		}
		laneScalarDigits := scalarDigits[laneIndex*chunks : (laneIndex+1)*chunks]
		borrows, err := apvssCompactComparatorBorrows(modulusDigits, laneScalarDigits, complements)
		if err != nil {
			return nil, err
		}
		for _, value := range complements {
			blinding, err := apvssRandomFr()
			if err != nil {
				return nil, err
			}
			commitment, err := apvssCompactRangeCommitment(value, blinding)
			if err != nil {
				return nil, err
			}
			complementValues = append(complementValues, value)
			complementBlindings = append(complementBlindings, blinding)
			proof.complementCommitments = append(proof.complementCommitments, commitment)
		}
		for _, value := range borrows {
			blinding, err := apvssRandomFr()
			if err != nil {
				return nil, err
			}
			commitment, err := apvssCompactRangeCommitment(value, blinding)
			if err != nil {
				return nil, err
			}
			borrowValues = append(borrowValues, value)
			borrowBlindings = append(borrowBlindings, blinding)
			proof.borrowCommitments = append(proof.borrowCommitments, commitment)
		}
	}
	statement, err := apvssCompactComparatorStatement(leaf, link, proof)
	if err != nil {
		return nil, err
	}
	proof.complementRange, err = apvssProveCompactRange(
		apvssCompactSubproofStatement(statement, "complement-range"),
		proof.complementCommitments,
		complementValues,
		complementBlindings,
		8,
	)
	if err != nil {
		return nil, err
	}
	proof.borrowRange, err = apvssProveCompactRange(
		apvssCompactSubproofStatement(statement, "borrow-range"),
		proof.borrowCommitments,
		borrowValues,
		borrowBlindings,
		1,
	)
	if err != nil {
		return nil, err
	}
	aggregate, aggregateBlinding, err := apvssCompactComparatorAggregate(
		statement,
		link,
		proof,
		modulusDigits,
		true,
		scalarBlindings,
		complementBlindings,
		borrowBlindings,
	)
	if err != nil {
		return nil, err
	}
	randomness, err := apvssRandomFr()
	if err != nil {
		return nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	proof.tRelation = cvPointTimes(&h, &randomness)
	challenge, err := apvssCompactChallenge(
		apvssCompactComparatorChallengeDomain,
		statement,
		apvssCompactPointBytes(&aggregate, &proof.tRelation),
	)
	if err != nil {
		return nil, err
	}
	proof.zRelation.Mul(&challenge, &aggregateBlinding).Add(&proof.zRelation, &randomness)
	return proof, nil
}

func apvssVerifyCompactComparator(
	leaf *cvLeaf,
	link *apvssCompactLinkProof,
	proof *apvssCompactComparatorProof,
) error {
	if leaf == nil || link == nil || proof == nil || !cvValidG1(&proof.tRelation, true) {
		return fmt.Errorf("invalid APVSS compact comparator proof")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return err
	}
	if len(proof.complementCommitments) != len(link.lanes)*chunks ||
		len(proof.borrowCommitments) != len(link.lanes)*(chunks-1) {
		return fmt.Errorf("invalid APVSS compact comparator shape")
	}
	statement, err := apvssCompactComparatorStatement(leaf, link, proof)
	if err != nil {
		return err
	}
	if err := apvssVerifyCompactRange(
		apvssCompactSubproofStatement(statement, "complement-range"),
		proof.complementCommitments,
		proof.complementRange,
		8,
	); err != nil {
		return fmt.Errorf("invalid APVSS comparator complement range: %w", err)
	}
	if err := apvssVerifyCompactRange(
		apvssCompactSubproofStatement(statement, "borrow-range"),
		proof.borrowCommitments,
		proof.borrowRange,
		1,
	); err != nil {
		return fmt.Errorf("invalid APVSS comparator borrow range: %w", err)
	}
	modulusDigits, err := apvssCompactModulusDigits(chunks)
	if err != nil {
		return err
	}
	aggregate, _, err := apvssCompactComparatorAggregate(
		statement, link, proof, modulusDigits, false, nil, nil, nil,
	)
	if err != nil {
		return err
	}
	challenge, err := apvssCompactChallenge(
		apvssCompactComparatorChallengeDomain,
		statement,
		apvssCompactPointBytes(&aggregate, &proof.tRelation),
	)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	left := cvPointTimes(&h, &proof.zRelation)
	right := cvPointSum(&proof.tRelation, pointPtr(cvPointTimes(&aggregate, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid APVSS canonical comparator relation")
	}
	return nil
}

func apvssProveCompactFallback(
	leaf *cvLeaf,
	witness *apvssDealerWitness,
	receiverIndices []int,
) (*apvssCompactFallbackProof, error) {
	var digitValues []uint64
	var digitBlindings []fr.Element
	link, err := apvssProveCompactLinkWithOpenings(
		leaf, witness, receiverIndices, &digitValues, &digitBlindings,
	)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactFallbackProof{link: link}
	proof.comparator, err = apvssProveCompactComparator(
		leaf, witness, link, digitValues, digitBlindings,
	)
	if err != nil {
		return nil, err
	}
	statement, err := apvssCompactComparatorStatement(leaf, link, proof.comparator)
	if err != nil {
		return nil, err
	}
	proof.digitRange, err = apvssProveCompactRange(
		apvssCompactSubproofStatement(statement, "scalar-digit-range"),
		apvssCompactLinkCommitments(link),
		digitValues,
		digitBlindings,
		8,
	)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func apvssVerifyCompactFallback(leaf *cvLeaf, proof *apvssCompactFallbackProof) error {
	if leaf == nil || proof == nil || proof.link == nil || proof.comparator == nil {
		return fmt.Errorf("invalid APVSS compact fallback proof")
	}
	if err := apvssVerifyCompactLink(leaf, proof.link); err != nil {
		return err
	}
	statement, err := apvssCompactComparatorStatement(leaf, proof.link, proof.comparator)
	if err != nil {
		return err
	}
	if err := apvssVerifyCompactRange(
		apvssCompactSubproofStatement(statement, "scalar-digit-range"),
		apvssCompactLinkCommitments(proof.link),
		proof.digitRange,
		8,
	); err != nil {
		return fmt.Errorf("invalid APVSS scalar digit range: %w", err)
	}
	return apvssVerifyCompactComparator(leaf, proof.link, proof.comparator)
}

func apvssCompactFallbackProofCanonicalBytes(
	leaf *cvLeaf,
	proof *apvssCompactFallbackProof,
) ([]byte, error) {
	if leaf == nil || proof == nil || proof.comparator == nil {
		return nil, fmt.Errorf("invalid APVSS compact fallback proof")
	}
	linkWire, err := apvssCompactLinkProofCanonicalBytes(leaf, proof.link)
	if err != nil {
		return nil, err
	}
	digitRangeWire, err := apvssCompactRangeProofCanonicalBytes(proof.digitRange)
	if err != nil {
		return nil, err
	}
	complementRangeWire, err := apvssCompactRangeProofCanonicalBytes(proof.comparator.complementRange)
	if err != nil {
		return nil, err
	}
	borrowRangeWire, err := apvssCompactRangeProofCanonicalBytes(proof.comparator.borrowRange)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	for _, field := range [][]byte{linkWire, digitRangeWire, complementRangeWire, borrowRangeWire} {
		if err := cvWriteBytes(&wire, field); err != nil {
			return nil, err
		}
	}
	if err := cvWritePointVector(&wire, proof.comparator.complementCommitments); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.comparator.borrowCommitments); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &proof.comparator.tRelation)
	cvWriteScalar(&wire, &proof.comparator.zRelation)
	return wire.Bytes(), nil
}

func apvssDecodeCompactFallbackProof(
	wire []byte,
	leaf *cvLeaf,
) (*apvssCompactFallbackProof, error) {
	return apvssDecodeCompactFallbackProofWithVerify(wire, leaf, true)
}

func apvssDecodeCompactFallbackProofWithVerify(
	wire []byte,
	leaf *cvLeaf,
	verify bool,
) (*apvssCompactFallbackProof, error) {
	if leaf == nil || len(wire) == 0 || len(wire) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid APVSS compact fallback wire")
	}
	r := newCVWireReader(wire)
	linkWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback link: %w", err)
	}
	link, err := apvssDecodeCompactLinkProof(linkWire, leaf)
	if err != nil {
		return nil, err
	}
	digitRangeWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback digit range: %w", err)
	}
	complementRangeWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback complement range: %w", err)
	}
	borrowRangeWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback borrow range: %w", err)
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	scalarCount := len(link.lanes) * chunks
	borrowCount := len(link.lanes) * (chunks - 1)
	proof := &apvssCompactFallbackProof{link: link, comparator: &apvssCompactComparatorProof{}}
	proof.comparator.complementCommitments, err = cvReadExactPointVector(
		r, scalarCount, "APVSS compact complement commitments",
	)
	if err != nil {
		return nil, err
	}
	proof.comparator.borrowCommitments, err = cvReadExactPointVector(
		r, borrowCount, "APVSS compact borrow commitments",
	)
	if err != nil {
		return nil, err
	}
	proof.comparator.tRelation, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact comparator relation point: %w", err)
	}
	proof.comparator.zRelation, err = r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS compact comparator relation scalar or suffix")
	}
	proof.digitRange, err = apvssDecodeCompactRangeProof(digitRangeWire, scalarCount, 8)
	if err != nil {
		return nil, err
	}
	proof.comparator.complementRange, err = apvssDecodeCompactRangeProof(
		complementRangeWire, scalarCount, 8,
	)
	if err != nil {
		return nil, err
	}
	proof.comparator.borrowRange, err = apvssDecodeCompactRangeProof(
		borrowRangeWire, borrowCount, 1,
	)
	if err != nil {
		return nil, err
	}
	canonical, err := apvssCompactFallbackProofCanonicalBytes(leaf, proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS compact fallback proof")
	}
	if verify {
		if err := apvssVerifyCompactFallback(leaf, proof); err != nil {
			return nil, err
		}
	}
	return proof, nil
}
