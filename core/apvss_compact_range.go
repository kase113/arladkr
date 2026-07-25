package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssCompactRangeDomainV1       = "ARL-APVSS-v1/compact-range"
	apvssCompactRangeGeneratorDSTV1 = "ARL-APVSS-v1/compact-range/H2C"
)

type apvssCompactInnerProductProofV1 struct {
	left  []bls12381.G1Affine
	right []bls12381.G1Affine
	a     fr.Element
	b     fr.Element
}

// apvssCompactRangeProofV1 is an aggregated Bulletproof range proof. It may
// prove any positive number of same-width values; the implementation pads the
// value count to a power of two with public zero commitments.
type apvssCompactRangeProofV1 struct {
	valueCount int
	bits       int
	a          bls12381.G1Affine
	s          bls12381.G1Affine
	t1         bls12381.G1Affine
	t2         bls12381.G1Affine
	tauX       fr.Element
	mu         fr.Element
	tHat       fr.Element
	inner      apvssCompactInnerProductProofV1
}

type apvssCompactRangeGeneratorsV1 struct {
	g []bls12381.G1Affine
	h []bls12381.G1Affine
	u bls12381.G1Affine
}

var apvssCompactRangeGeneratorCacheV1 sync.Map

func apvssNextPowerOfTwoV1(value int) (int, error) {
	if value <= 0 || value > 1<<20 {
		return 0, fmt.Errorf("invalid APVSS compact vector size")
	}
	out := 1
	for out < value {
		out <<= 1
	}
	return out, nil
}

func apvssCompactRangeDimensionsV1(valueCount, bits int) (int, int, error) {
	if valueCount <= 0 || bits <= 0 || bits > 63 {
		return 0, 0, fmt.Errorf("invalid APVSS compact range dimensions")
	}
	paddedValues, err := apvssNextPowerOfTwoV1(valueCount)
	if err != nil {
		return 0, 0, err
	}
	vectorSize, err := apvssNextPowerOfTwoV1(paddedValues * bits)
	if err != nil || vectorSize != paddedValues*bits {
		return 0, 0, fmt.Errorf("APVSS compact range width must be a power of two")
	}
	return paddedValues, vectorSize, nil
}

func apvssCompactRangeGeneratorV1(kind byte, index int) (bls12381.G1Affine, error) {
	message := make([]byte, 9)
	message[0] = kind
	binary.BigEndian.PutUint64(message[1:], uint64(index))
	point, err := bls12381.HashToG1(message, []byte(apvssCompactRangeGeneratorDSTV1))
	if err != nil || !cvValidG1(&point, false) || point.Equal(&genG1) {
		return bls12381.G1Affine{}, fmt.Errorf("derive APVSS compact range generator %d/%d", kind, index)
	}
	return point, nil
}

func apvssCompactRangeGeneratorsForV1(size int) (*apvssCompactRangeGeneratorsV1, error) {
	if cached, ok := apvssCompactRangeGeneratorCacheV1.Load(size); ok {
		return cached.(*apvssCompactRangeGeneratorsV1), nil
	}
	generators := &apvssCompactRangeGeneratorsV1{
		g: make([]bls12381.G1Affine, size),
		h: make([]bls12381.G1Affine, size),
	}
	var err error
	for i := 0; i < size; i++ {
		generators.g[i], err = apvssCompactRangeGeneratorV1('G', i)
		if err != nil {
			return nil, err
		}
		generators.h[i], err = apvssCompactRangeGeneratorV1('H', i)
		if err != nil {
			return nil, err
		}
	}
	generators.u, err = apvssCompactRangeGeneratorV1('U', 0)
	if err != nil {
		return nil, err
	}
	actual, _ := apvssCompactRangeGeneratorCacheV1.LoadOrStore(size, generators)
	return actual.(*apvssCompactRangeGeneratorsV1), nil
}

func apvssCompactIdentityV1() bls12381.G1Affine {
	var identity bls12381.G1Affine
	identity.ScalarMultiplication(&genG1, big.NewInt(0))
	return identity
}

func apvssCompactPointSumV1(points []bls12381.G1Affine, scalars []fr.Element) bls12381.G1Affine {
	if len(points) == len(scalars) && len(points) >= 32 {
		var out bls12381.G1Affine
		if _, err := out.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: 8}); err == nil {
			return out
		}
	}
	out := apvssCompactIdentityV1()
	for i := range points {
		term := cvPointTimes(&points[i], &scalars[i])
		out.Add(&out, &term)
	}
	return out
}

func apvssCompactInnerProductV1(left, right []fr.Element) fr.Element {
	var out fr.Element
	for i := range left {
		var term fr.Element
		term.Mul(&left[i], &right[i])
		out.Add(&out, &term)
	}
	return out
}

func apvssCompactScalarPowersV1(base fr.Element, count int) []fr.Element {
	out := make([]fr.Element, count)
	if count == 0 {
		return out
	}
	out[0].SetOne()
	for i := 1; i < count; i++ {
		out[i].Mul(&out[i-1], &base)
	}
	return out
}

func apvssCompactRangeBaseTranscriptV1(
	statement []byte,
	commitments []bls12381.G1Affine,
	valueCount, bits int,
) ([]byte, error) {
	if len(statement) != 32 || len(commitments) != valueCount {
		return nil, fmt.Errorf("invalid APVSS compact range statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssCompactRangeDomainV1)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, statement); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, valueCount); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, bits); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, commitments); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func apvssCompactChallengeV1(domain string, parts ...[]byte) (fr.Element, error) {
	challenge, err := cvHashToFrV1(domain, parts...)
	if err != nil {
		return fr.Element{}, err
	}
	if challenge.IsZero() {
		return fr.Element{}, fmt.Errorf("zero APVSS compact proof challenge")
	}
	return challenge, nil
}

func apvssCompactPointBytesV1(points ...*bls12381.G1Affine) []byte {
	var wire bytes.Buffer
	for _, point := range points {
		cvWritePoint(&wire, point)
	}
	return wire.Bytes()
}

func apvssCompactScalarBytesV1(scalars ...*fr.Element) []byte {
	var wire bytes.Buffer
	for _, scalar := range scalars {
		cvWriteScalar(&wire, scalar)
	}
	return wire.Bytes()
}

func apvssCompactRangeCommitmentV1(value uint64, blinding fr.Element) (bls12381.G1Affine, error) {
	h, err := cvPedersenBase()
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	var scalar fr.Element
	scalar.SetUint64(value)
	return cvPointSum(
		pointPtr(cvPointTimes(&genG1, &scalar)),
		pointPtr(cvPointTimes(&h, &blinding)),
	), nil
}

func apvssProveCompactRangeV1(
	statement []byte,
	commitments []bls12381.G1Affine,
	values []uint64,
	blindings []fr.Element,
	bits int,
) (*apvssCompactRangeProofV1, error) {
	if len(commitments) == 0 || len(commitments) != len(values) || len(values) != len(blindings) {
		return nil, fmt.Errorf("invalid APVSS compact range witness")
	}
	paddedValues, vectorSize, err := apvssCompactRangeDimensionsV1(len(values), bits)
	if err != nil {
		return nil, err
	}
	if bits < 64 {
		limit := uint64(1) << uint(bits)
		for i, value := range values {
			if value >= limit {
				return nil, fmt.Errorf("APVSS compact range value %d is outside [0,2^%d)", i, bits)
			}
		}
	}
	for i := range values {
		expected, err := apvssCompactRangeCommitmentV1(values[i], blindings[i])
		if err != nil || !expected.Equal(&commitments[i]) {
			return nil, fmt.Errorf("APVSS compact range opening mismatch %d", i)
		}
	}
	baseTranscript, err := apvssCompactRangeBaseTranscriptV1(statement, commitments, len(values), bits)
	if err != nil {
		return nil, err
	}
	generators, err := apvssCompactRangeGeneratorsForV1(vectorSize)
	if err != nil {
		return nil, err
	}
	hBlind, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	aL := make([]fr.Element, vectorSize)
	aR := make([]fr.Element, vectorSize)
	sL := make([]fr.Element, vectorSize)
	sR := make([]fr.Element, vectorSize)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var value uint64
		if valueIndex < len(values) {
			value = values[valueIndex]
		}
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			aL[index].SetUint64((value >> uint(bit)) & 1)
			one := fr.One()
			aR[index].Sub(&aL[index], &one)
		}
	}
	for i := range sL {
		sL[i], err = apvssRandomFrV1()
		if err != nil {
			return nil, err
		}
		sR[i], err = apvssRandomFrV1()
		if err != nil {
			return nil, err
		}
	}
	alpha, err := apvssRandomFrV1()
	if err != nil {
		return nil, err
	}
	rho, err := apvssRandomFrV1()
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactRangeProofV1{valueCount: len(values), bits: bits}
	proof.a = apvssCompactPointSumV1(generators.g, aL)
	proof.a.Add(&proof.a, pointPtr(apvssCompactPointSumV1(generators.h, aR)))
	proof.a.Add(&proof.a, pointPtr(cvPointTimes(&hBlind, &alpha)))
	proof.s = apvssCompactPointSumV1(generators.g, sL)
	proof.s.Add(&proof.s, pointPtr(apvssCompactPointSumV1(generators.h, sR)))
	proof.s.Add(&proof.s, pointPtr(cvPointTimes(&hBlind, &rho)))

	firstMove := apvssCompactPointBytesV1(&proof.a, &proof.s)
	y, err := apvssCompactChallengeV1(apvssCompactRangeDomainV1+"/y", baseTranscript, firstMove)
	if err != nil {
		return nil, err
	}
	yBytes := apvssCompactScalarBytesV1(&y)
	z, err := apvssCompactChallengeV1(apvssCompactRangeDomainV1+"/z", baseTranscript, firstMove, yBytes)
	if err != nil {
		return nil, err
	}
	yPowers := apvssCompactScalarPowersV1(y, vectorSize)
	zTwo := make([]fr.Element, vectorSize)
	var zPower fr.Element
	zPower.Mul(&z, &z)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var two fr.Element
		two.SetOne()
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			zTwo[index].Mul(&zPower, &two)
			two.Double(&two)
		}
		zPower.Mul(&zPower, &z)
	}
	l0 := make([]fr.Element, vectorSize)
	l1 := make([]fr.Element, vectorSize)
	r0 := make([]fr.Element, vectorSize)
	r1 := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		l0[i].Sub(&aL[i], &z)
		l1[i].Set(&sL[i])
		var shifted fr.Element
		shifted.Add(&aR[i], &z)
		r0[i].Mul(&yPowers[i], &shifted).Add(&r0[i], &zTwo[i])
		r1[i].Mul(&yPowers[i], &sR[i])
	}
	t1Left := apvssCompactInnerProductV1(l1, r0)
	t1Right := apvssCompactInnerProductV1(l0, r1)
	var t1, t2 fr.Element
	t1.Add(&t1Left, &t1Right)
	t2 = apvssCompactInnerProductV1(l1, r1)
	tau1, err := apvssRandomFrV1()
	if err != nil {
		return nil, err
	}
	tau2, err := apvssRandomFrV1()
	if err != nil {
		return nil, err
	}
	proof.t1 = cvPointSum(pointPtr(cvPointTimes(&genG1, &t1)), pointPtr(cvPointTimes(&hBlind, &tau1)))
	proof.t2 = cvPointSum(pointPtr(cvPointTimes(&genG1, &t2)), pointPtr(cvPointTimes(&hBlind, &tau2)))
	secondMove := apvssCompactPointBytesV1(&proof.t1, &proof.t2)
	x, err := apvssCompactChallengeV1(
		apvssCompactRangeDomainV1+"/x", baseTranscript, firstMove, yBytes,
		apvssCompactScalarBytesV1(&z), secondMove,
	)
	if err != nil {
		return nil, err
	}
	var xSquared fr.Element
	xSquared.Mul(&x, &x)
	l := make([]fr.Element, vectorSize)
	r := make([]fr.Element, vectorSize)
	for i := range l {
		var term fr.Element
		term.Mul(&l1[i], &x)
		l[i].Add(&l0[i], &term)
		term.Mul(&r1[i], &x)
		r[i].Add(&r0[i], &term)
	}
	proof.tHat = apvssCompactInnerProductV1(l, r)
	proof.tauX.Mul(&tau2, &xSquared)
	var tauTerm fr.Element
	tauTerm.Mul(&tau1, &x)
	proof.tauX.Add(&proof.tauX, &tauTerm)
	zPower.Mul(&z, &z)
	for i := 0; i < paddedValues; i++ {
		if i < len(blindings) {
			tauTerm.Mul(&zPower, &blindings[i])
			proof.tauX.Add(&proof.tauX, &tauTerm)
		}
		zPower.Mul(&zPower, &z)
	}
	proof.mu.Mul(&rho, &x).Add(&proof.mu, &alpha)
	w, err := apvssCompactChallengeV1(
		apvssCompactRangeDomainV1+"/w",
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytesV1(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
	)
	if err != nil {
		return nil, err
	}
	uPrime := cvPointTimes(&generators.u, &w)

	hPrime := make([]bls12381.G1Affine, vectorSize)
	var yInverse fr.Element
	yInverse.Inverse(&y)
	yInversePowers := apvssCompactScalarPowersV1(yInverse, vectorSize)
	for i := range hPrime {
		hPrime[i] = cvPointTimes(&generators.h[i], &yInversePowers[i])
	}
	p := proof.a
	p.Add(&p, pointPtr(cvPointTimes(&proof.s, &x)))
	var minusZ fr.Element
	minusZ.Neg(&z)
	gCoefficients := make([]fr.Element, vectorSize)
	hCoefficients := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		gCoefficients[i].Set(&minusZ)
		hCoefficients[i].Mul(&z, &yPowers[i]).Add(&hCoefficients[i], &zTwo[i])
	}
	p.Add(&p, pointPtr(apvssCompactPointSumV1(generators.g, gCoefficients)))
	p.Add(&p, pointPtr(apvssCompactPointSumV1(hPrime, hCoefficients)))
	var minusMu fr.Element
	minusMu.Neg(&proof.mu)
	p.Add(&p, pointPtr(cvPointTimes(&hBlind, &minusMu)))
	p.Add(&p, pointPtr(cvPointTimes(&uPrime, &proof.tHat)))
	innerPrefix := cvTranscriptBytes(
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytesV1(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
		apvssCompactPointBytesV1(&p),
	)
	proof.inner, err = apvssProveCompactInnerProductV1(innerPrefix, generators.g, hPrime, uPrime, l, r)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func apvssCompactRangeDeltaV1(y, z fr.Element, paddedValues, bits, vectorSize int) fr.Element {
	yPowers := apvssCompactScalarPowersV1(y, vectorSize)
	var sumY fr.Element
	for i := range yPowers {
		sumY.Add(&sumY, &yPowers[i])
	}
	var zSquared, first fr.Element
	zSquared.Mul(&z, &z)
	first.Sub(&z, &zSquared).Mul(&first, &sumY)
	var twoSum fr.Element
	twoSum.SetUint64((uint64(1) << uint(bits)) - 1)
	var subtract, zPower fr.Element
	zPower.Mul(&zSquared, &z)
	for i := 0; i < paddedValues; i++ {
		var term fr.Element
		term.Mul(&zPower, &twoSum)
		subtract.Add(&subtract, &term)
		zPower.Mul(&zPower, &z)
	}
	first.Sub(&first, &subtract)
	return first
}

func apvssVerifyCompactRangeV1(
	statement []byte,
	commitments []bls12381.G1Affine,
	proof *apvssCompactRangeProofV1,
	bits int,
) error {
	if proof == nil || proof.valueCount != len(commitments) || proof.bits != bits {
		return fmt.Errorf("invalid APVSS compact range proof shape")
	}
	paddedValues, vectorSize, err := apvssCompactRangeDimensionsV1(len(commitments), bits)
	if err != nil {
		return err
	}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		if !cvValidG1(point, true) {
			return fmt.Errorf("invalid APVSS compact range proof point")
		}
	}
	baseTranscript, err := apvssCompactRangeBaseTranscriptV1(statement, commitments, len(commitments), bits)
	if err != nil {
		return err
	}
	firstMove := apvssCompactPointBytesV1(&proof.a, &proof.s)
	y, err := apvssCompactChallengeV1(apvssCompactRangeDomainV1+"/y", baseTranscript, firstMove)
	if err != nil {
		return err
	}
	yBytes := apvssCompactScalarBytesV1(&y)
	z, err := apvssCompactChallengeV1(apvssCompactRangeDomainV1+"/z", baseTranscript, firstMove, yBytes)
	if err != nil {
		return err
	}
	secondMove := apvssCompactPointBytesV1(&proof.t1, &proof.t2)
	x, err := apvssCompactChallengeV1(
		apvssCompactRangeDomainV1+"/x", baseTranscript, firstMove, yBytes,
		apvssCompactScalarBytesV1(&z), secondMove,
	)
	if err != nil {
		return err
	}
	hBlind, err := cvPedersenBase()
	if err != nil {
		return err
	}
	left := cvPointSum(
		pointPtr(cvPointTimes(&genG1, &proof.tHat)),
		pointPtr(cvPointTimes(&hBlind, &proof.tauX)),
	)
	delta := apvssCompactRangeDeltaV1(y, z, paddedValues, bits, vectorSize)
	right := cvPointTimes(&genG1, &delta)
	var zPower fr.Element
	zPower.Mul(&z, &z)
	for i := 0; i < paddedValues; i++ {
		if i < len(commitments) {
			right.Add(&right, pointPtr(cvPointTimes(&commitments[i], &zPower)))
		}
		zPower.Mul(&zPower, &z)
	}
	right.Add(&right, pointPtr(cvPointTimes(&proof.t1, &x)))
	var xSquared fr.Element
	xSquared.Mul(&x, &x)
	right.Add(&right, pointPtr(cvPointTimes(&proof.t2, &xSquared)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid APVSS compact range polynomial commitment")
	}
	generators, err := apvssCompactRangeGeneratorsForV1(vectorSize)
	if err != nil {
		return err
	}
	w, err := apvssCompactChallengeV1(
		apvssCompactRangeDomainV1+"/w",
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytesV1(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
	)
	if err != nil {
		return err
	}
	uPrime := cvPointTimes(&generators.u, &w)
	yPowers := apvssCompactScalarPowersV1(y, vectorSize)
	var yInverse fr.Element
	yInverse.Inverse(&y)
	yInversePowers := apvssCompactScalarPowersV1(yInverse, vectorSize)
	hPrime := make([]bls12381.G1Affine, vectorSize)
	for i := range hPrime {
		hPrime[i] = cvPointTimes(&generators.h[i], &yInversePowers[i])
	}
	zTwo := make([]fr.Element, vectorSize)
	zPower.Mul(&z, &z)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var two fr.Element
		two.SetOne()
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			zTwo[index].Mul(&zPower, &two)
			two.Double(&two)
		}
		zPower.Mul(&zPower, &z)
	}
	p := proof.a
	p.Add(&p, pointPtr(cvPointTimes(&proof.s, &x)))
	var minusZ fr.Element
	minusZ.Neg(&z)
	gCoefficients := make([]fr.Element, vectorSize)
	hCoefficients := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		gCoefficients[i].Set(&minusZ)
		hCoefficients[i].Mul(&z, &yPowers[i]).Add(&hCoefficients[i], &zTwo[i])
	}
	p.Add(&p, pointPtr(apvssCompactPointSumV1(generators.g, gCoefficients)))
	p.Add(&p, pointPtr(apvssCompactPointSumV1(hPrime, hCoefficients)))
	var minusMu fr.Element
	minusMu.Neg(&proof.mu)
	p.Add(&p, pointPtr(cvPointTimes(&hBlind, &minusMu)))
	p.Add(&p, pointPtr(cvPointTimes(&uPrime, &proof.tHat)))
	innerPrefix := cvTranscriptBytes(
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytesV1(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
		apvssCompactPointBytesV1(&p),
	)
	if err := apvssVerifyCompactInnerProductV1(innerPrefix, generators.g, hPrime, uPrime, p, &proof.inner); err != nil {
		return fmt.Errorf("invalid APVSS compact range inner product: %w", err)
	}
	return nil
}

func apvssCompactInnerChallengeV1(prefix []byte, round int, left, right *bls12381.G1Affine) (fr.Element, error) {
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(round))
	return apvssCompactChallengeV1(
		apvssCompactRangeDomainV1+"/inner",
		prefix,
		index[:],
		apvssCompactPointBytesV1(left, right),
	)
}

func apvssProveCompactInnerProductV1(
	prefix []byte,
	g, h []bls12381.G1Affine,
	u bls12381.G1Affine,
	a, b []fr.Element,
) (apvssCompactInnerProductProofV1, error) {
	if len(g) == 0 || len(g) != len(h) || len(g) != len(a) || len(a) != len(b) || len(g)&(len(g)-1) != 0 {
		return apvssCompactInnerProductProofV1{}, fmt.Errorf("invalid APVSS inner-product witness")
	}
	gWork := append([]bls12381.G1Affine(nil), g...)
	hWork := append([]bls12381.G1Affine(nil), h...)
	aWork := append([]fr.Element(nil), a...)
	bWork := append([]fr.Element(nil), b...)
	proof := apvssCompactInnerProductProofV1{}
	transcript := append([]byte(nil), prefix...)
	for round := 0; len(aWork) > 1; round++ {
		half := len(aWork) / 2
		aLeft, aRight := aWork[:half], aWork[half:]
		bLeft, bRight := bWork[:half], bWork[half:]
		left := apvssCompactPointSumV1(gWork[half:], aLeft)
		left.Add(&left, pointPtr(apvssCompactPointSumV1(hWork[:half], bRight)))
		leftInner := apvssCompactInnerProductV1(aLeft, bRight)
		left.Add(&left, pointPtr(cvPointTimes(&u, &leftInner)))
		right := apvssCompactPointSumV1(gWork[:half], aRight)
		right.Add(&right, pointPtr(apvssCompactPointSumV1(hWork[half:], bLeft)))
		rightInner := apvssCompactInnerProductV1(aRight, bLeft)
		right.Add(&right, pointPtr(cvPointTimes(&u, &rightInner)))
		proof.left = append(proof.left, left)
		proof.right = append(proof.right, right)
		roundPoints := apvssCompactPointBytesV1(&left, &right)
		x, err := apvssCompactInnerChallengeV1(transcript, round, &left, &right)
		if err != nil {
			return apvssCompactInnerProductProofV1{}, err
		}
		transcript = cvTranscriptBytes(transcript, roundPoints)
		var xInverse fr.Element
		xInverse.Inverse(&x)
		gNext := make([]bls12381.G1Affine, half)
		hNext := make([]bls12381.G1Affine, half)
		aNext := make([]fr.Element, half)
		bNext := make([]fr.Element, half)
		for i := 0; i < half; i++ {
			gNext[i] = cvPointSum(
				pointPtr(cvPointTimes(&gWork[i], &xInverse)),
				pointPtr(cvPointTimes(&gWork[half+i], &x)),
			)
			hNext[i] = cvPointSum(
				pointPtr(cvPointTimes(&hWork[i], &x)),
				pointPtr(cvPointTimes(&hWork[half+i], &xInverse)),
			)
			var term fr.Element
			aNext[i].Mul(&x, &aLeft[i])
			term.Mul(&xInverse, &aRight[i])
			aNext[i].Add(&aNext[i], &term)
			bNext[i].Mul(&xInverse, &bLeft[i])
			term.Mul(&x, &bRight[i])
			bNext[i].Add(&bNext[i], &term)
		}
		gWork, hWork, aWork, bWork = gNext, hNext, aNext, bNext
	}
	proof.a.Set(&aWork[0])
	proof.b.Set(&bWork[0])
	return proof, nil
}

func apvssVerifyCompactInnerProductV1(
	prefix []byte,
	g, h []bls12381.G1Affine,
	u bls12381.G1Affine,
	p bls12381.G1Affine,
	proof *apvssCompactInnerProductProofV1,
) error {
	if proof == nil || len(g) == 0 || len(g) != len(h) || len(g)&(len(g)-1) != 0 ||
		len(proof.left) != len(proof.right) || 1<<uint(len(proof.left)) != len(g) {
		return fmt.Errorf("invalid APVSS inner-product proof shape")
	}
	gWork := append([]bls12381.G1Affine(nil), g...)
	hWork := append([]bls12381.G1Affine(nil), h...)
	pWork := p
	transcript := append([]byte(nil), prefix...)
	for round := range proof.left {
		left, right := &proof.left[round], &proof.right[round]
		if !cvValidG1(left, true) || !cvValidG1(right, true) {
			return fmt.Errorf("invalid APVSS inner-product point %d", round)
		}
		roundPoints := apvssCompactPointBytesV1(left, right)
		x, err := apvssCompactInnerChallengeV1(transcript, round, left, right)
		if err != nil {
			return err
		}
		transcript = cvTranscriptBytes(transcript, roundPoints)
		var xInverse, xSquared, xInverseSquared fr.Element
		xInverse.Inverse(&x)
		xSquared.Mul(&x, &x)
		xInverseSquared.Mul(&xInverse, &xInverse)
		pWork.Add(&pWork, pointPtr(cvPointTimes(left, &xSquared)))
		pWork.Add(&pWork, pointPtr(cvPointTimes(right, &xInverseSquared)))
		half := len(gWork) / 2
		gNext := make([]bls12381.G1Affine, half)
		hNext := make([]bls12381.G1Affine, half)
		for i := 0; i < half; i++ {
			gNext[i] = cvPointSum(
				pointPtr(cvPointTimes(&gWork[i], &xInverse)),
				pointPtr(cvPointTimes(&gWork[half+i], &x)),
			)
			hNext[i] = cvPointSum(
				pointPtr(cvPointTimes(&hWork[i], &x)),
				pointPtr(cvPointTimes(&hWork[half+i], &xInverse)),
			)
		}
		gWork, hWork = gNext, hNext
	}
	right := cvPointSum(
		pointPtr(cvPointTimes(&gWork[0], &proof.a)),
		pointPtr(cvPointTimes(&hWork[0], &proof.b)),
	)
	var product fr.Element
	product.Mul(&proof.a, &proof.b)
	right.Add(&right, pointPtr(cvPointTimes(&u, &product)))
	if !pWork.Equal(&right) {
		return fmt.Errorf("APVSS inner-product equation mismatch")
	}
	return nil
}

func apvssCompactRangeProofV1CanonicalBytes(proof *apvssCompactRangeProofV1) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil APVSS compact range proof")
	}
	var wire bytes.Buffer
	if err := cvWriteUint32(&wire, proof.valueCount); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, proof.bits); err != nil {
		return nil, err
	}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		if !cvValidG1(point, true) {
			return nil, fmt.Errorf("invalid APVSS compact range point")
		}
		cvWritePoint(&wire, point)
	}
	for _, scalar := range []*fr.Element{&proof.tauX, &proof.mu, &proof.tHat} {
		cvWriteScalar(&wire, scalar)
	}
	if err := cvWriteUint32(&wire, len(proof.inner.left)); err != nil {
		return nil, err
	}
	for i := range proof.inner.left {
		cvWritePoint(&wire, &proof.inner.left[i])
		cvWritePoint(&wire, &proof.inner.right[i])
	}
	cvWriteScalar(&wire, &proof.inner.a)
	cvWriteScalar(&wire, &proof.inner.b)
	return wire.Bytes(), nil
}

func apvssDecodeCompactRangeProofV1(
	wire []byte,
	expectedValues, expectedBits int,
) (*apvssCompactRangeProofV1, error) {
	if len(wire) == 0 || len(wire) > cvMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("invalid APVSS compact range wire")
	}
	r := newCVWireReader(wire)
	valueCount, err := r.uint32()
	if err != nil || valueCount != expectedValues {
		return nil, fmt.Errorf("invalid APVSS compact range value count")
	}
	bits, err := r.uint32()
	if err != nil || bits != expectedBits {
		return nil, fmt.Errorf("invalid APVSS compact range width")
	}
	_, vectorSize, err := apvssCompactRangeDimensionsV1(valueCount, bits)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactRangeProofV1{valueCount: valueCount, bits: bits}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		*point, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range point: %w", err)
		}
	}
	for _, scalar := range []*fr.Element{&proof.tauX, &proof.mu, &proof.tHat} {
		*scalar, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range scalar: %w", err)
		}
	}
	rounds, err := r.uint32()
	wantRounds := 0
	for size := vectorSize; size > 1; size >>= 1 {
		wantRounds++
	}
	if err != nil || rounds != wantRounds {
		return nil, fmt.Errorf("invalid APVSS compact range inner-product rounds")
	}
	proof.inner.left = make([]bls12381.G1Affine, rounds)
	proof.inner.right = make([]bls12381.G1Affine, rounds)
	for i := 0; i < rounds; i++ {
		proof.inner.left[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range inner left %d: %w", i, err)
		}
		proof.inner.right[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range inner right %d: %w", i, err)
		}
	}
	proof.inner.a, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact range inner a: %w", err)
	}
	proof.inner.b, err = r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS compact range inner b or suffix")
	}
	canonical, err := apvssCompactRangeProofV1CanonicalBytes(proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS compact range proof")
	}
	return proof, nil
}
