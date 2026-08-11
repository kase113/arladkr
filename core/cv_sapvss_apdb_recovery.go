package core

import (
	"bytes"
	"fmt"
	"sync"
)

// cvAPDBRecoveryCollectorV2 validates authenticated holder responses before
// passing a threshold set to the deterministic APDB reconstruction routine.
type cvAPDBRecoveryCollectorV2 struct {
	mu             sync.Mutex
	lock           cvAPDBLockV2
	requestWire    []byte
	oldRoster      []int
	memberIndex    map[int]int
	dataShards     int
	totalShards    int
	shardBytes     int
	maximumPayload int
	bindingCheck   func([]byte) error
	stores         map[int]cvAPDBStoreV2
	storeWires     map[int][]byte
}

func newCVAPDBRecoveryCollectorV2(
	lock *cvAPDBLockV2, oldRoster []int, dataShards, shardBytes, maximumPayload int,
	apdbSigner *tblsThresholdSigner, bindingCheck func([]byte) error,
) (*cvAPDBRecoveryCollectorV2, error) {
	if len(oldRoster) == 0 || !equalInts(oldRoster, sortedUnique(oldRoster)) || dataShards <= 0 ||
		dataShards > len(oldRoster) || shardBytes <= 0 || maximumPayload <= 0 ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) || !equalInts(apdbSigner.memberOrder, oldRoster) ||
		cvVerifyAPDBLockV2(lock, apdbSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery collector configuration")
	}
	memberIndex := make(map[int]int, len(oldRoster))
	for index, member := range oldRoster {
		if member < 0 {
			return nil, fmt.Errorf("invalid CV V2 APDB recovery roster")
		}
		memberIndex[member] = index
	}
	return &cvAPDBRecoveryCollectorV2{
		lock: cvAPDBLockV2{
			InstanceDigest: append([]byte(nil), lock.InstanceDigest...),
			Root:           append([]byte(nil), lock.Root...),
			Certificate:    append([]byte(nil), lock.Certificate...),
		},
		oldRoster:      append([]int(nil), oldRoster...),
		memberIndex:    memberIndex,
		dataShards:     dataShards,
		totalShards:    len(oldRoster),
		shardBytes:     shardBytes,
		maximumPayload: maximumPayload,
		bindingCheck:   bindingCheck,
		stores:         make(map[int]cvAPDBStoreV2, dataShards),
		storeWires:     make(map[int][]byte, dataShards),
	}, nil
}

func newCVAggregateRecoveryCollectorV2(
	requestWire, expectedContext []byte, oldRoster []int, dataShards, shardBytes, maximumPayload int,
	apdbSigner, controlSigner *tblsThresholdSigner, bindingCheck func([]byte) error,
) (*cvAPDBRecoveryCollectorV2, error) {
	handoff, err := cvAuthorizeAggregateRecoveryRequestV2(requestWire, expectedContext, apdbSigner, controlSigner)
	if err != nil {
		return nil, err
	}
	collector, err := newCVAPDBRecoveryCollectorV2(
		&handoff.ARC, oldRoster, dataShards, shardBytes, maximumPayload, apdbSigner, bindingCheck,
	)
	if err != nil {
		return nil, err
	}
	collector.requestWire = append([]byte(nil), requestWire...)
	return collector, nil
}

// RequestRecipients returns every holder because a compact APDB lock does not
// reveal which members contributed shares to its threshold certificate.
func (c *cvAPDBRecoveryCollectorV2) RequestRecipients() []int {
	if c == nil {
		return nil
	}
	return append([]int(nil), c.oldRoster...)
}

func (c *cvAPDBRecoveryCollectorV2) RequestWire() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.requestWire...)
}

func (c *cvAPDBRecoveryCollectorV2) AddStore(from int, wire []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("nil CV V2 APDB recovery collector")
	}
	expectedIndex, member := c.memberIndex[from]
	if !member {
		return false, fmt.Errorf("CV V2 APDB recovery response from non-holder")
	}
	store, err := cvDecodeAPDBStoreV2(wire, c.totalShards, c.shardBytes)
	if err != nil {
		return false, err
	}
	if store.Index != expectedIndex || !bytes.Equal(store.InstanceDigest, c.lock.InstanceDigest) ||
		!bytes.Equal(store.Root, c.lock.Root) {
		return false, fmt.Errorf("CV V2 APDB recovery response does not match holder or lock")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if previous, exists := c.storeWires[expectedIndex]; exists {
		if !bytes.Equal(previous, wire) {
			return false, fmt.Errorf("conflicting CV V2 APDB recovery response")
		}
		return len(c.stores) >= c.dataShards, nil
	}
	c.stores[expectedIndex] = cvAPDBStoreV2{
		InstanceDigest: append([]byte(nil), store.InstanceDigest...),
		Root:           append([]byte(nil), store.Root...),
		Index:          store.Index,
		Shard:          append([]byte(nil), store.Shard...),
		Siblings:       cvCloneByteSlices(store.Siblings),
	}
	c.storeWires[expectedIndex] = append([]byte(nil), wire...)
	return len(c.stores) >= c.dataShards, nil
}

func (c *cvAPDBRecoveryCollectorV2) Recover() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil CV V2 APDB recovery collector")
	}
	c.mu.Lock()
	if len(c.stores) < c.dataShards {
		c.mu.Unlock()
		return nil, fmt.Errorf("insufficient CV V2 APDB recovery responses")
	}
	stores := make([]cvAPDBStoreV2, 0, len(c.stores))
	for index := 0; index < c.totalShards; index++ {
		if store, ok := c.stores[index]; ok {
			stores = append(stores, store)
		}
	}
	c.mu.Unlock()
	return cvRecoverAPDBV2(
		&c.lock, stores, c.dataShards, c.totalShards, c.shardBytes, c.maximumPayload, c.bindingCheck,
	)
}
