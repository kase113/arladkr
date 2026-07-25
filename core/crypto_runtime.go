package core

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type runtimeCrypto struct {
	oldOrder      []int
	oldIndex      map[int]int
	receiverOrder []int
	receiverIndex map[int]int

	lockSigner     *tblsThresholdSigner
	fastlaneSigner *tblsThresholdSigner
	coinSigner     *tblsThresholdSigner

	receiverStates map[int]ReceiverState
	vePublicKeys   map[int]*PaillierPublicKey
	vePrivateKeys  map[int]*PaillierPrivateKey

	// BLS12-381 PVSS key material (Bacho-Loss CCS'23)
	blsPVSSSecretKeys map[int]fr.Element
	blsPVSSPublicKeys map[int]bls12381.G2Affine
	commMetrics       bool

	admitAggMu             sync.Mutex
	admitAggAttempts       int
	admitAggPasses         int
	validatedAggRLOs       map[string][]byte
	validatedDescriptors   map[string][]byte
	validatedArtifacts     map[string][]byte
	preparedARCShares      map[string]ARCHeaderShare
	trustedReadyCandidates []readyCandidate
	fallbackProposalCache  map[string][]byte
	cachedAggregates       map[string]*APVSSAggregate
	cachedAggRLOs          map[string]*AggRLO

	commMu         sync.Mutex
	totalSentBytes uint64
	totalRecvBytes uint64
	commPhase      string
	phaseSentBytes map[string]uint64
	phaseRecvBytes map[string]uint64
}

func ensureRuntime(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	*cfg = NormalizeConfig(*cfg)
	if cfg.runtime != nil {
		return nil
	}
	if len(cfg.OldCommittee) == 0 || len(cfg.NewCommittee) == 0 {
		return nil
	}
	if cfg.Epoch > 1 && len(cfg.InputReceiverStates) == 0 && cfg.StateStoreDir != "" {
		states, err := loadReceiverStatesFromStore(cfg)
		if err != nil {
			return err
		}
		if len(states) > 0 {
			cfg.InputReceiverStates = states
		}
	}

	oldOrder := sortedCopy(cfg.OldCommittee)
	receiverOrder := sortedCopy(cfg.NewCommittee)
	useBlsPWSS := strings.EqualFold(cfg.APVSSProvider, "bls-pvss")
	useCVSAPVSS := strings.EqualFold(cfg.APVSSProvider, "cv-sapvss")
	oldIndex := make(map[int]int, len(oldOrder))
	for i, id := range oldOrder {
		oldIndex[id] = i
	}
	receiverIndex := make(map[int]int, len(receiverOrder))
	for i, id := range receiverOrder {
		receiverIndex[id] = i
	}

	lockThreshold := len(oldOrder) - cfg.FOld
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	var lockSigner *tblsThresholdSigner
	hasCVKeyDir := strings.TrimSpace(cfg.CVPublicKeyDir) != "" || strings.TrimSpace(cfg.CVLocalSecretDir) != ""
	if useCVSAPVSS && hasCVKeyDir {
		if strings.TrimSpace(cfg.CVPublicKeyDir) == "" || strings.TrimSpace(cfg.CVLocalSecretDir) == "" {
			return fmt.Errorf("CV old-lock runtime requires both public and local secret key directories")
		}
		material, err := cvLoadOldLockKeyMaterialV1(
			cfg.CVPublicKeyDir, cfg.CVLocalSecretDir, cfg.SID,
			oldOrder, lockThreshold, localOldNodes(*cfg),
		)
		if err != nil {
			return fmt.Errorf("load CV old-lock key material: %w", err)
		}
		lockSigner, err = newTBLSThresholdSignerFromMaterial(material)
		if err != nil {
			return err
		}
	} else {
		if useCVSAPVSS && cfg.StrictNetwork {
			return fmt.Errorf("strict CV runtime requires materialized old-lock key directories")
		}
		var err error
		lockSigner, err = newTBLSThresholdSigner(
			oldOrder,
			lockThreshold,
			deterministicStream(
				"rladkr-lock-signer",
				[]byte(cfg.SID),
				[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
				encodeInts(oldOrder),
			),
		)
		if err != nil {
			return err
		}
	}

	fastThreshold := 2*cfg.FOld + 1
	if fastThreshold <= 0 {
		fastThreshold = 1
	}
	if fastThreshold > len(oldOrder) {
		fastThreshold = len(oldOrder)
	}
	fastlaneSigner, err := newTBLSThresholdSigner(
		oldOrder,
		fastThreshold,
		deterministicStream(
			"rladkr-fastlane-signer",
			[]byte(cfg.SID),
			[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
			encodeInts(oldOrder),
		),
	)
	if err != nil {
		return err
	}
	coinThreshold := cfg.FOld + 1
	if coinThreshold <= 0 {
		coinThreshold = 1
	}
	if coinThreshold > len(oldOrder) {
		coinThreshold = len(oldOrder)
	}
	coinSigner, err := newTBLSThresholdSigner(
		oldOrder,
		coinThreshold,
		deterministicStream(
			"rladkr-coin-signer",
			[]byte(cfg.SID),
			[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
			encodeInts(oldOrder),
		),
	)
	if err != nil {
		return err
	}

	// Step A: BLS PVSS keypairs for ALL members (old committee = dealers for NIZK;
	// new committee = receivers for share decryption).
	blsPVSSSecretKeys := make(map[int]fr.Element)
	blsPVSSPublicKeys := make(map[int]bls12381.G2Affine)
	if !useCVSAPVSS {
		allMembers := sortedUnique(append(append([]int(nil), oldOrder...), receiverOrder...))
		for _, id := range allMembers {
			blsSkStream := deterministicStream(
				"rladkr-blspvss-key",
				[]byte(cfg.SID),
				[]byte(fmt.Sprintf("|member=%d", id)),
			)
			buf := make([]byte, fr.Bytes)
			blsSkStream.XORKeyStream(buf, buf)
			var blsSk fr.Element
			blsSk.SetBytes(buf[:fr.Bytes])
			var blsPk bls12381.G2Affine
			blsPk.ScalarMultiplication(&genG2, blsSk.BigInt(new(big.Int)))
			blsPVSSSecretKeys[id] = blsSk
			blsPVSSPublicKeys[id] = blsPk
		}
	}

	// Step B: Receiver states + Paillier VE keys (only for new committee).
	receiverStates := make(map[int]ReceiverState, len(receiverOrder))
	vePublicKeys := make(map[int]*PaillierPublicKey, len(receiverOrder))
	vePrivateKeys := make(map[int]*PaillierPrivateKey, len(receiverOrder))
	for _, id := range receiverOrder {
		if useCVSAPVSS {
			continue
		}
		var state ReceiverState
		if st, ok := cfg.InputReceiverStates[id]; ok {
			state = cloneReceiverState(st)
			if state.NodeID != id {
				state.NodeID = id
			}
			if state.Epoch != cfg.Epoch {
				return fmt.Errorf(
					"receiver state epoch mismatch for id=%d: have=%d need=%d",
					id,
					state.Epoch,
					cfg.Epoch,
				)
			}
			if len(state.SecretKey) == 0 || len(state.PublicKey) == 0 {
				return fmt.Errorf("receiver state missing key material for id=%d", id)
			}
			if _, err := publicKeyFromRaw(state.PublicKey); err != nil {
				return fmt.Errorf("invalid receiver public key for id=%d: %w", id, err)
			}
			if _, err := privateKeyFromRaw(state.SecretKey); err != nil {
				return fmt.Errorf("invalid receiver secret key for id=%d: %w", id, err)
			}
			if len(state.ChainKey) == 0 {
				state.ChainKey = hashBytes(
					[]byte("rladkr-rfs-chain-fallback"),
					[]byte(cfg.SID),
					[]byte(fmt.Sprintf("|epoch=%d|receiver=%d", cfg.Epoch, id)),
				)
			}
		} else {
			if cfg.Epoch > 1 {
				return fmt.Errorf("missing receiver state for id=%d at epoch=%d", id, cfg.Epoch)
			}
			var initErr error
			state, initErr = rfsInitState(*cfg, id)
			if initErr != nil {
				return initErr
			}
		}
		receiverStates[id] = state

		if !useBlsPWSS {
			veKey, veErr := loadOrCreateVEKeyCache(cfg, id)
			if veErr != nil {
				return fmt.Errorf("generate VE key for receiver=%d failed: %w", id, veErr)
			}
			vePublicKeys[id] = veKey.PublicKey
			vePrivateKeys[id] = veKey
		}
	}

	cfg.runtime = &runtimeCrypto{
		oldOrder:              oldOrder,
		oldIndex:              oldIndex,
		receiverOrder:         receiverOrder,
		receiverIndex:         receiverIndex,
		lockSigner:            lockSigner,
		fastlaneSigner:        fastlaneSigner,
		coinSigner:            coinSigner,
		receiverStates:        receiverStates,
		vePublicKeys:          vePublicKeys,
		vePrivateKeys:         vePrivateKeys,
		blsPVSSSecretKeys:     blsPVSSSecretKeys,
		blsPVSSPublicKeys:     blsPVSSPublicKeys,
		commMetrics:           cfg.CommMetrics,
		validatedAggRLOs:      make(map[string][]byte),
		validatedDescriptors:  make(map[string][]byte),
		validatedArtifacts:    make(map[string][]byte),
		preparedARCShares:     make(map[string]ARCHeaderShare),
		fallbackProposalCache: make(map[string][]byte),
		cachedAggregates:      make(map[string]*APVSSAggregate),
		cachedAggRLOs:         make(map[string]*AggRLO),
		phaseSentBytes:        make(map[string]uint64),
		phaseRecvBytes:        make(map[string]uint64),
	}
	return nil
}

func loadReceiverStatesFromStore(cfg *Config) (map[int]ReceiverState, error) {
	if cfg == nil || cfg.StateStoreDir == "" {
		return nil, nil
	}
	store := newReceiverStateStore(cfg.StateStoreDir)
	states, err := store.Load(cfg.SID, cfg.Epoch)
	if err != nil {
		return nil, fmt.Errorf("load receiver states from store failed: %w", err)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}

func deterministicStream(label string, parts ...[]byte) cipher.Stream {
	keySeedParts := make([][]byte, 0, len(parts)+1)
	keySeedParts = append(keySeedParts, []byte(label))
	keySeedParts = append(keySeedParts, parts...)
	keySeed := hashBytes(keySeedParts...)
	ivSeed := hashBytes(append(keySeedParts, []byte("|iv"))...)

	block, _ := aes.NewCipher(keySeed[:32])
	return cipher.NewCTR(block, ivSeed[:aes.BlockSize])
}

func (r *runtimeCrypto) recordSentBytes(n int) {
	if r == nil || !r.commMetrics || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.totalSentBytes += uint64(n)
	if r.commPhase != "" {
		r.phaseSentBytes[r.commPhase] += uint64(n)
	}
	r.commMu.Unlock()
}

func (r *runtimeCrypto) recordRecvBytes(n int) {
	if r == nil || !r.commMetrics || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.totalRecvBytes += uint64(n)
	if r.commPhase != "" {
		r.phaseRecvBytes[r.commPhase] += uint64(n)
	}
	r.commMu.Unlock()
}

func (r *runtimeCrypto) commStats() (uint64, uint64) {
	if r == nil {
		return 0, 0
	}
	r.commMu.Lock()
	defer r.commMu.Unlock()
	return r.totalSentBytes, r.totalRecvBytes
}

func (r *runtimeCrypto) setCommPhase(name string) {
	if r == nil {
		return
	}
	r.commMu.Lock()
	r.commPhase = name
	r.commMu.Unlock()
}

func (r *runtimeCrypto) commPhaseName() string {
	if r == nil {
		return ""
	}
	r.commMu.Lock()
	defer r.commMu.Unlock()
	return r.commPhase
}

func (r *runtimeCrypto) phaseCommStats() (map[string]uint64, map[string]uint64) {
	if r == nil {
		return nil, nil
	}
	r.commMu.Lock()
	defer r.commMu.Unlock()
	sent := make(map[string]uint64, len(r.phaseSentBytes))
	recv := make(map[string]uint64, len(r.phaseRecvBytes))
	for k, v := range r.phaseSentBytes {
		sent[k] = v
	}
	for k, v := range r.phaseRecvBytes {
		recv[k] = v
	}
	return sent, recv
}

type tblsThresholdSigner struct {
	t int
	n int

	pubKey       bls12381.G2Affine   // group public key = secret * G2
	pubKeyShares []bls12381.G2Affine // individual pk_i = share_i * G2
	shares       []fr.Element        // secret key shares

	memberOrder    []int
	memberIndex    map[int]int
	signingMembers map[int]struct{}
}

var _, _, genG1, genG2 = bls12381.Generators()

func newTBLSThresholdSigner(members []int, threshold int, stream cipher.Stream) (*tblsThresholdSigner, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("empty members")
	}
	if threshold <= 0 || threshold > len(members) {
		return nil, fmt.Errorf("invalid threshold: %d", threshold)
	}

	n := len(members)
	// Generate BLS12-381 t-out-of-n threshold keys via Shamir secret sharing
	coeffs := make([]fr.Element, threshold)
	for j := 0; j < threshold; j++ {
		buf := make([]byte, fr.Bytes)
		stream.XORKeyStream(buf, buf)
		coeffs[j].SetBytes(buf[:fr.Bytes])
	}

	shares := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var x fr.Element
		x.SetInt64(int64(i + 1))
		shares[i].SetZero()
		xPow := new(fr.Element)
		xPow.SetOne()
		for j := 0; j < threshold; j++ {
			var term fr.Element
			term.Mul(&coeffs[j], xPow)
			shares[i].Add(&shares[i], &term)
			xPow.Mul(xPow, &x)
		}
	}

	// Compute public key shares: pk_i = share_i * G2
	pubKeyShares := make([]bls12381.G2Affine, n)
	for i := 0; i < n; i++ {
		pubKeyShares[i].ScalarMultiplication(&genG2, shares[i].BigInt(new(big.Int)))
	}

	// Group public key = coeffs[0] * G2
	var pubKey bls12381.G2Affine
	pubKey.ScalarMultiplication(&genG2, coeffs[0].BigInt(new(big.Int)))

	memberOrder := sortedCopy(members)
	memberIndex := make(map[int]int, len(memberOrder))
	for i, id := range memberOrder {
		memberIndex[id] = i
	}

	return &tblsThresholdSigner{
		t:            threshold,
		n:            n,
		pubKey:       pubKey,
		pubKeyShares: pubKeyShares,
		shares:       shares,
		memberOrder:  memberOrder,
		memberIndex:  memberIndex,
	}, nil
}

func newTBLSThresholdSignerFromMaterial(material *cvOldLockKeyMaterialV1) (*tblsThresholdSigner, error) {
	if material == nil || material.threshold <= 0 || material.threshold > len(material.members) ||
		len(material.publicShares) != len(material.members) || len(material.localShares) == 0 {
		return nil, fmt.Errorf("invalid CV old-lock signer material")
	}
	memberIndex := make(map[int]int, len(material.members))
	shares := make([]fr.Element, len(material.members))
	for i, member := range material.members {
		memberIndex[member] = i
		if share, ok := material.localShares[member]; ok {
			shares[i] = share
		}
	}
	return &tblsThresholdSigner{
		t: material.threshold, n: len(material.members), pubKey: material.groupPublic,
		pubKeyShares: append([]bls12381.G2Affine(nil), material.publicShares...), shares: shares,
		memberOrder: append([]int(nil), material.members...), memberIndex: memberIndex,
		signingMembers: nodeSet(materialMemberIDsV1(material.localShares)),
	}, nil
}

func materialMemberIDsV1(shares map[int]fr.Element) []int {
	ids := make([]int, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	return ids
}

func (s *tblsThresholdSigner) Threshold() int {
	return s.t
}

func (s *tblsThresholdSigner) restrictSigningTo(members []int) {
	s.signingMembers = nodeSet(members)
}

// SignShare produces a BLS signature share on G1: H(m)^share_i
func (s *tblsThresholdSigner) SignShare(member int, domain string, digest []byte) ([]byte, error) {
	idx, ok := s.memberIndex[member]
	if !ok {
		return nil, fmt.Errorf("unknown member: %d", member)
	}
	if s.signingMembers != nil {
		if _, ok := s.signingMembers[member]; !ok {
			return nil, fmt.Errorf("member %d has no local signing share", member)
		}
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("hash to G1: %w", err)
	}
	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&h, s.shares[idx].BigInt(new(big.Int)))
	return sig.Marshal(), nil
}

// VerifyShare checks e(sig_i, G2) == e(H(m), pk_i)
func (s *tblsThresholdSigner) VerifyShare(member int, domain string, digest []byte, sigBytes []byte) bool {
	idx, ok := s.memberIndex[member]
	if !ok || idx >= len(s.pubKeyShares) {
		return false
	}
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil {
		return false
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return false
	}
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKeyShares[idx])
	ok, _ = bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{genG2, negPK},
	)
	return ok
}

// Recover reconstructs the full BLS signature via Lagrange interpolation over G1.
func (s *tblsThresholdSigner) Recover(domain string, digest []byte, sharesMap map[int][]byte) ([]byte, error) {
	if len(sharesMap) < s.t {
		return nil, fmt.Errorf("insufficient shares: have=%d need=%d", len(sharesMap), s.t)
	}
	memberIDs := make([]int, 0, len(sharesMap))
	for id := range sharesMap {
		memberIDs = append(memberIDs, id)
	}
	sort.Slice(memberIDs, func(i, j int) bool {
		return s.memberIndex[memberIDs[i]] < s.memberIndex[memberIDs[j]]
	})

	// Lagrange coefficients
	ids := make([]int, len(memberIDs))
	for i, mid := range memberIDs {
		ids[i] = s.memberIndex[mid] + 1 // use 1-based index
	}
	coeffs := make([]fr.Element, len(ids))
	for i, id1 := range ids {
		coeffs[i].SetOne()
		for _, id2 := range ids {
			if id1 == id2 {
				continue
			}
			num := new(big.Int).SetInt64(int64(id2))
			den := new(big.Int).SetInt64(int64(id2 - id1))
			var nf, df fr.Element
			nf.SetBigInt(num)
			df.SetBigInt(den)
			df.Inverse(&df)
			nf.Mul(&nf, &df)
			coeffs[i].Mul(&coeffs[i], &nf)
		}
	}

	var recovered bls12381.G1Affine
	zero := big.NewInt(0)
	recovered.ScalarMultiplication(&genG1, zero)
	for i, mid := range memberIDs {
		var sig bls12381.G1Affine
		if err := sig.Unmarshal(sharesMap[mid]); err != nil {
			return nil, fmt.Errorf("unmarshal share %d: %w", mid, err)
		}
		var term bls12381.G1Affine
		term.ScalarMultiplication(&sig, coeffs[i].BigInt(new(big.Int)))
		recovered.Add(&recovered, &term)
	}
	return recovered.Marshal(), nil
}

// VerifyRecovered checks e(sig, G2) == e(H(m), PK)
func (s *tblsThresholdSigner) VerifyRecovered(domain string, digest, sigBytes []byte) bool {
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil {
		return false
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return false
	}
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKey)
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{genG2, negPK},
	)
	return ok
}

func domainDigest(domain string, digest []byte) []byte {
	return hashBytes(
		[]byte("rladkr-domain"),
		[]byte(strings.ToUpper(domain)),
		digest,
	)
}

func (r *runtimeCrypto) receiverState(id int) (ReceiverState, bool) {
	if r == nil || r.receiverStates == nil {
		return ReceiverState{}, false
	}
	st, ok := r.receiverStates[id]
	if !ok {
		return ReceiverState{}, false
	}
	return cloneReceiverState(st), true
}

func (r *runtimeCrypto) vePublicKey(id int) (*PaillierPublicKey, bool) {
	if r == nil || r.vePublicKeys == nil {
		return nil, false
	}
	pk, ok := r.vePublicKeys[id]
	return pk, ok
}

func (r *runtimeCrypto) vePrivateKey(id int) (*PaillierPrivateKey, bool) {
	if r == nil || r.vePrivateKeys == nil {
		return nil, false
	}
	sk, ok := r.vePrivateKeys[id]
	return sk, ok
}

func (r *runtimeCrypto) blsPVSSSecretKey(id int) (fr.Element, bool) {
	if r == nil || r.blsPVSSSecretKeys == nil {
		return fr.Element{}, false
	}
	sk, ok := r.blsPVSSSecretKeys[id]
	return sk, ok
}

func (r *runtimeCrypto) blsPVSSPublicKey(id int) (bls12381.G2Affine, bool) {
	if r == nil || r.blsPVSSPublicKeys == nil {
		var zero bls12381.G2Affine
		return zero, false
	}
	pk, ok := r.blsPVSSPublicKeys[id]
	return pk, ok
}

func (r *runtimeCrypto) recordAdmitAgg(pass bool) {
	if r == nil {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.admitAggAttempts++
	if pass {
		r.admitAggPasses++
	}
}

func (r *runtimeCrypto) cachePreparedARCShare(share ARCHeaderShare) {
	if r == nil {
		return
	}
	key := preparedARCShareKey(share.Holder, share.Epoch, share.AggHeaderDigest)
	r.admitAggMu.Lock()
	r.preparedARCShares[key] = cloneARCHeaderShare(share)
	r.admitAggMu.Unlock()
}

func (r *runtimeCrypto) preparedARCShare(holder int, epoch int, digest []byte) (ARCHeaderShare, bool) {
	if r == nil {
		return ARCHeaderShare{}, false
	}
	key := preparedARCShareKey(holder, epoch, digest)
	r.admitAggMu.Lock()
	share, ok := r.preparedARCShares[key]
	r.admitAggMu.Unlock()
	if !ok {
		return ARCHeaderShare{}, false
	}
	return cloneARCHeaderShare(share), true
}

func preparedARCShareKey(holder int, epoch int, digest []byte) string {
	return fmt.Sprintf("%d|%d|%x", holder, epoch, digest)
}

func cloneARCHeaderShare(in ARCHeaderShare) ARCHeaderShare {
	return ARCHeaderShare{
		Holder:          in.Holder,
		Epoch:           in.Epoch,
		AggHeaderDigest: append([]byte(nil), in.AggHeaderDigest...),
		ObligationKind:  in.ObligationKind,
		Signature:       append([]byte(nil), in.Signature...),
	}
}

func (r *runtimeCrypto) admitAggStats() (int, int) {
	if r == nil {
		return 0, 0
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	return r.admitAggAttempts, r.admitAggPasses
}

func (r *runtimeCrypto) rememberValidatedAggRLO(digest []byte, fingerprint []byte) {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.validatedAggRLOs[string(digest)] = append([]byte(nil), fingerprint...)
}

func (r *runtimeCrypto) hasValidatedAggRLO(digest []byte, fingerprint []byte) bool {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	cached, ok := r.validatedAggRLOs[string(digest)]
	return ok && bytesEq(cached, fingerprint)
}

func (r *runtimeCrypto) rememberValidatedDescriptor(digest []byte, fingerprint []byte) {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.validatedDescriptors[string(digest)] = append([]byte(nil), fingerprint...)
}

func (r *runtimeCrypto) hasValidatedDescriptor(digest []byte, fingerprint []byte) bool {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	cached, ok := r.validatedDescriptors[string(digest)]
	return ok && bytesEq(cached, fingerprint)
}

func (r *runtimeCrypto) rememberValidatedArtifact(digest []byte, fingerprint []byte) {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.validatedArtifacts[string(digest)] = append([]byte(nil), fingerprint...)
}

func (r *runtimeCrypto) hasValidatedArtifact(digest []byte, fingerprint []byte) bool {
	if r == nil || len(digest) == 0 || len(fingerprint) == 0 {
		return false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	cached, ok := r.validatedArtifacts[string(digest)]
	return ok && bytesEq(cached, fingerprint)
}

func (r *runtimeCrypto) cachedFallbackProposal(key string) ([]byte, bool) {
	if r == nil || strings.TrimSpace(key) == "" {
		return nil, false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	cached, ok := r.fallbackProposalCache[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), cached...), true
}

func (r *runtimeCrypto) rememberFallbackProposal(key string, blob []byte) {
	if r == nil || strings.TrimSpace(key) == "" || len(blob) == 0 {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.fallbackProposalCache[key] = append([]byte(nil), blob...)
}

func (r *runtimeCrypto) cachedAggregateBuild(key string) (*APVSSAggregate, bool) {
	if r == nil || strings.TrimSpace(key) == "" {
		return nil, false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	agg, ok := r.cachedAggregates[key]
	if !ok || agg == nil {
		return nil, false
	}
	return cloneAPVSSAggregate(agg), true
}

func (r *runtimeCrypto) rememberAggregateBuild(key string, agg *APVSSAggregate) {
	if r == nil || strings.TrimSpace(key) == "" || agg == nil {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.cachedAggregates[key] = cloneAPVSSAggregate(agg)
}

func (r *runtimeCrypto) cachedAggRLOBuild(key string) (*AggRLO, bool) {
	if r == nil || strings.TrimSpace(key) == "" {
		return nil, false
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	rlo, ok := r.cachedAggRLOs[key]
	if !ok || rlo == nil {
		return nil, false
	}
	return cloneAggRLO(rlo), true
}

func (r *runtimeCrypto) rememberAggRLOBuild(key string, rlo *AggRLO) {
	if r == nil || strings.TrimSpace(key) == "" || rlo == nil {
		return
	}
	r.admitAggMu.Lock()
	defer r.admitAggMu.Unlock()
	r.cachedAggRLOs[key] = cloneAggRLO(rlo)
}
