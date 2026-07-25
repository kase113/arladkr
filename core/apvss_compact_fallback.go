package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssCompactFallbackDomainV1            = "ARL-APVSS-v1/compact-fallback"
	apvssCompactComparatorStatementDomainV1 = "ARL-APVSS-v1/canonical-comparator/statement"
	apvssCompactComparatorWeightDomainV1    = "ARL-APVSS-v1/canonical-comparator/weight"
	apvssCompactComparatorChallengeDomainV1 = "ARL-APVSS-v1/canonical-comparator/challenge"
)

type apvssCompactComparatorProofV1 struct {
	complementCommitments []bls12381.G1Affine
	borrowCommitments     []bls12381.G1Affine
	complementRange       *apvssCompactRangeProofV1
	borrowRange           *apvssCompactRangeProofV1
	tRelation             bls12381.G1Affine
	zRelation             fr.Element
}

type apvssCompactFallbackProofV1 struct {
	link       *apvssCompactLinkProofV1
	digitRange *apvssCompactRangeProofV1
	comparator *apvssCompactComparatorProofV1
}

func apvssCompactLinkCommitmentsV1(proof *apvssCompactLinkProofV1) []bls12381.G1Affine {
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

func apvssCompactModulusDigitsV1(count int) ([]uint64, error) {
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

func apvssCompactComplementDigitsV1(scalar fr.Element, count int) ([]uint64, error) {
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

func apvssCompactComparatorBorrowsV1(
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

func apvssCompactComparatorStatementV1(
	leaf *cvLeafV1,
	link *apvssCompactLinkProofV1,
	proof *apvssCompactComparatorProofV1,
) ([]byte, error) {
	if leaf == nil || link == nil || proof == nil {
		return nil, fmt.Errorf("invalid APVSS comparator statement")
	}
	fallbackDigest, err := apvssFallbackSetStatementDigestV1(
		leaf,
		apvssCompactLinkReceiverIndicesV1(link),
		apvssFallbackCompactBatchProfileV1,
	)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssCompactComparatorStatementDomainV1)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, fallbackDigest); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, apvssCompactLinkCommitmentsV1(link)); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.complementCommitments); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.borrowCommitments); err != nil {
		return nil, err
	}
	return hashBytes([]byte(apvssCompactComparatorStatementDomainV1), wire.Bytes()), nil
}

func apvssCompactSubproofStatementV1(statement []byte, label string) []byte {
	return hashBytes([]byte(apvssCompactFallbackDomainV1+"/"+label), statement)
}

func apvssCompactComparatorAggregateV1(
	statement []byte,
	link *apvssCompactLinkProofV1,
	proof *apvssCompactComparatorProofV1,
	modulusDigits []uint64,
	withBlindings bool,
	scalarBlindings, complementBlindings, borrowBlindings []fr.Element,
) (bls12381.G1Affine, fr.Element, error) {
	weight, err := apvssCompactChallengeV1(apvssCompactComparatorWeightDomainV1, statement)
	if err != nil {
		return bls12381.G1Affine{}, fr.Element{}, err
	}
	weights := apvssCompactScalarPowersV1(weight, len(proof.complementCommitments))
	scalarCommitments := apvssCompactLinkCommitmentsV1(link)
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
	aggregate := apvssCompactPointSumV1(points, coefficients)
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

func apvssProveCompactComparatorV1(
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	link *apvssCompactLinkProofV1,
	scalarDigits []uint64,
	scalarBlindings []fr.Element,
) (*apvssCompactComparatorProofV1, error) {
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
	modulusDigits, err := apvssCompactModulusDigitsV1(chunks)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactComparatorProofV1{
		complementCommitments: make([]bls12381.G1Affine, 0, len(scalarDigits)),
		borrowCommitments:     make([]bls12381.G1Affine, 0, len(link.lanes)*(chunks-1)),
	}
	complementValues := make([]uint64, 0, len(scalarDigits))
	complementBlindings := make([]fr.Element, 0, len(scalarDigits))
	borrowValues := make([]uint64, 0, len(link.lanes)*(chunks-1))
	borrowBlindings := make([]fr.Element, 0, len(link.lanes)*(chunks-1))
	for laneIndex, lane := range link.lanes {
		witnessIndex := lane.receiverIndex - 1
		complements, err := apvssCompactComplementDigitsV1(witness.scalars[witnessIndex], chunks)
		if err != nil {
			return nil, err
		}
		laneScalarDigits := scalarDigits[laneIndex*chunks : (laneIndex+1)*chunks]
		borrows, err := apvssCompactComparatorBorrowsV1(modulusDigits, laneScalarDigits, complements)
		if err != nil {
			return nil, err
		}
		for _, value := range complements {
			blinding, err := apvssRandomFrV1()
			if err != nil {
				return nil, err
			}
			commitment, err := apvssCompactRangeCommitmentV1(value, blinding)
			if err != nil {
				return nil, err
			}
			complementValues = append(complementValues, value)
			complementBlindings = append(complementBlindings, blinding)
			proof.complementCommitments = append(proof.complementCommitments, commitment)
		}
		for _, value := range borrows {
			blinding, err := apvssRandomFrV1()
			if err != nil {
				return nil, err
			}
			commitment, err := apvssCompactRangeCommitmentV1(value, blinding)
			if err != nil {
				return nil, err
			}
			borrowValues = append(borrowValues, value)
			borrowBlindings = append(borrowBlindings, blinding)
			proof.borrowCommitments = append(proof.borrowCommitments, commitment)
		}
	}
	statement, err := apvssCompactComparatorStatementV1(leaf, link, proof)
	if err != nil {
		return nil, err
	}
	proof.complementRange, err = apvssProveCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "complement-range"),
		proof.complementCommitments,
		complementValues,
		complementBlindings,
		8,
	)
	if err != nil {
		return nil, err
	}
	proof.borrowRange, err = apvssProveCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "borrow-range"),
		proof.borrowCommitments,
		borrowValues,
		borrowBlindings,
		1,
	)
	if err != nil {
		return nil, err
	}
	aggregate, aggregateBlinding, err := apvssCompactComparatorAggregateV1(
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
	randomness, err := apvssRandomFrV1()
	if err != nil {
		return nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	proof.tRelation = cvPointTimes(&h, &randomness)
	challenge, err := apvssCompactChallengeV1(
		apvssCompactComparatorChallengeDomainV1,
		statement,
		apvssCompactPointBytesV1(&aggregate, &proof.tRelation),
	)
	if err != nil {
		return nil, err
	}
	proof.zRelation.Mul(&challenge, &aggregateBlinding).Add(&proof.zRelation, &randomness)
	return proof, nil
}

func apvssVerifyCompactComparatorV1(
	leaf *cvLeafV1,
	link *apvssCompactLinkProofV1,
	proof *apvssCompactComparatorProofV1,
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
	statement, err := apvssCompactComparatorStatementV1(leaf, link, proof)
	if err != nil {
		return err
	}
	if err := apvssVerifyCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "complement-range"),
		proof.complementCommitments,
		proof.complementRange,
		8,
	); err != nil {
		return fmt.Errorf("invalid APVSS comparator complement range: %w", err)
	}
	if err := apvssVerifyCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "borrow-range"),
		proof.borrowCommitments,
		proof.borrowRange,
		1,
	); err != nil {
		return fmt.Errorf("invalid APVSS comparator borrow range: %w", err)
	}
	modulusDigits, err := apvssCompactModulusDigitsV1(chunks)
	if err != nil {
		return err
	}
	aggregate, _, err := apvssCompactComparatorAggregateV1(
		statement, link, proof, modulusDigits, false, nil, nil, nil,
	)
	if err != nil {
		return err
	}
	challenge, err := apvssCompactChallengeV1(
		apvssCompactComparatorChallengeDomainV1,
		statement,
		apvssCompactPointBytesV1(&aggregate, &proof.tRelation),
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

func apvssProveCompactFallbackV1(
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	receiverIndices []int,
) (*apvssCompactFallbackProofV1, error) {
	var digitValues []uint64
	var digitBlindings []fr.Element
	link, err := apvssProveCompactLinkWithOpeningsV1(
		leaf, witness, receiverIndices, &digitValues, &digitBlindings,
	)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactFallbackProofV1{link: link}
	proof.comparator, err = apvssProveCompactComparatorV1(
		leaf, witness, link, digitValues, digitBlindings,
	)
	if err != nil {
		return nil, err
	}
	statement, err := apvssCompactComparatorStatementV1(leaf, link, proof.comparator)
	if err != nil {
		return nil, err
	}
	proof.digitRange, err = apvssProveCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "scalar-digit-range"),
		apvssCompactLinkCommitmentsV1(link),
		digitValues,
		digitBlindings,
		8,
	)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func apvssVerifyCompactFallbackV1(leaf *cvLeafV1, proof *apvssCompactFallbackProofV1) error {
	if leaf == nil || proof == nil || proof.link == nil || proof.comparator == nil {
		return fmt.Errorf("invalid APVSS compact fallback proof")
	}
	if err := apvssVerifyCompactLinkV1(leaf, proof.link); err != nil {
		return err
	}
	statement, err := apvssCompactComparatorStatementV1(leaf, proof.link, proof.comparator)
	if err != nil {
		return err
	}
	if err := apvssVerifyCompactRangeV1(
		apvssCompactSubproofStatementV1(statement, "scalar-digit-range"),
		apvssCompactLinkCommitmentsV1(proof.link),
		proof.digitRange,
		8,
	); err != nil {
		return fmt.Errorf("invalid APVSS scalar digit range: %w", err)
	}
	return apvssVerifyCompactComparatorV1(leaf, proof.link, proof.comparator)
}

func apvssCompactFallbackProofV1CanonicalBytes(
	leaf *cvLeafV1,
	proof *apvssCompactFallbackProofV1,
) ([]byte, error) {
	if leaf == nil || proof == nil || proof.comparator == nil {
		return nil, fmt.Errorf("invalid APVSS compact fallback proof")
	}
	linkWire, err := apvssCompactLinkProofV1CanonicalBytes(leaf, proof.link)
	if err != nil {
		return nil, err
	}
	digitRangeWire, err := apvssCompactRangeProofV1CanonicalBytes(proof.digitRange)
	if err != nil {
		return nil, err
	}
	complementRangeWire, err := apvssCompactRangeProofV1CanonicalBytes(proof.comparator.complementRange)
	if err != nil {
		return nil, err
	}
	borrowRangeWire, err := apvssCompactRangeProofV1CanonicalBytes(proof.comparator.borrowRange)
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

func apvssDecodeCompactFallbackProofV1(
	wire []byte,
	leaf *cvLeafV1,
) (*apvssCompactFallbackProofV1, error) {
	return apvssDecodeCompactFallbackProofWithVerifyV1(wire, leaf, true)
}

func apvssDecodeCompactFallbackProofWithVerifyV1(
	wire []byte,
	leaf *cvLeafV1,
	verify bool,
) (*apvssCompactFallbackProofV1, error) {
	if leaf == nil || len(wire) == 0 || len(wire) > cvMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("invalid APVSS compact fallback wire")
	}
	r := newCVWireReader(wire)
	linkWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback link: %w", err)
	}
	link, err := apvssDecodeCompactLinkProofV1(linkWire, leaf)
	if err != nil {
		return nil, err
	}
	digitRangeWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback digit range: %w", err)
	}
	complementRangeWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback complement range: %w", err)
	}
	borrowRangeWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact fallback borrow range: %w", err)
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	scalarCount := len(link.lanes) * chunks
	borrowCount := len(link.lanes) * (chunks - 1)
	proof := &apvssCompactFallbackProofV1{link: link, comparator: &apvssCompactComparatorProofV1{}}
	proof.comparator.complementCommitments, err = cvReadExactPointVectorV1(
		r, scalarCount, "APVSS compact complement commitments",
	)
	if err != nil {
		return nil, err
	}
	proof.comparator.borrowCommitments, err = cvReadExactPointVectorV1(
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
	proof.digitRange, err = apvssDecodeCompactRangeProofV1(digitRangeWire, scalarCount, 8)
	if err != nil {
		return nil, err
	}
	proof.comparator.complementRange, err = apvssDecodeCompactRangeProofV1(
		complementRangeWire, scalarCount, 8,
	)
	if err != nil {
		return nil, err
	}
	proof.comparator.borrowRange, err = apvssDecodeCompactRangeProofV1(
		borrowRangeWire, borrowCount, 1,
	)
	if err != nil {
		return nil, err
	}
	canonical, err := apvssCompactFallbackProofV1CanonicalBytes(leaf, proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS compact fallback proof")
	}
	if verify {
		if err := apvssVerifyCompactFallbackV1(leaf, proof); err != nil {
			return nil, err
		}
	}
	return proof, nil
}
