package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	cvNetworkEnvelopeVersionV1     = byte(1)
	cvMaxNetworkEnvelopeSIDBytesV1 = 1 << 20
	cvMaxNetworkPayloadBytesV1     = cvMaxLeafWireBytesV1 + 1<<20
	cvNetworkEnvelopeFixedBytesV1  = 1 + 4 + 8 + 4
	cvTagComponentInitV1           = "CV_COMPONENT_INIT"
	cvTagComponentAckV1            = "CV_COMPONENT_ACK"
	cvTagComponentCertV1           = "CV_COMPONENT_CERT"
	cvTagComponentGetV1            = "CV_COMPONENT_GET"
	cvTagComponentLeafV1           = "CV_COMPONENT_LEAF"
	cvTagComponentReadyV1          = "CV_COMPONENT_READY"
	cvTagAggregateShardV1          = "CV_AGG_SHARD"
	cvTagARCShareV1                = "CV_ARC_SHARE"
	cvTagRecoverGetV1              = "CV_RECOVER_GET"
	cvTagRecoverShardV1            = "CV_RECOVER_SHARD"
	cvTagRecoverDoneV1             = "CV_RECOVER_DONE"
	cvTagReceiptV1                 = "CV_RECEIPT"
	cvTagReceiptDoneV1             = "CV_RECEIPT_DONE"
	apvssTagLaneOfferV1            = "APVSS_LANE_OFFER"
	apvssTagLaneACKV1              = "APVSS_LANE_ACK"
)

func cvAllowedNetworkTagV1(tag string) bool {
	switch tag {
	case cvTagComponentInitV1,
		cvTagComponentAckV1,
		cvTagComponentCertV1,
		cvTagComponentGetV1,
		cvTagComponentLeafV1,
		cvTagComponentReadyV1,
		cvTagAggregateShardV1,
		cvTagARCShareV1,
		cvTagRecoverGetV1,
		cvTagRecoverShardV1,
		cvTagRecoverDoneV1,
		cvTagReceiptV1,
		cvTagReceiptDoneV1,
		apvssTagLaneOfferV1,
		apvssTagLaneACKV1:
		return true
	default:
		return false
	}
}

func cvEncodeNetworkEnvelopeV1(sid string, epoch int, payload []byte) ([]byte, error) {
	if sid == "" || len(sid) > cvMaxNetworkEnvelopeSIDBytesV1 || epoch < 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS network envelope context")
	}
	if len(payload) > cvMaxNetworkPayloadBytesV1 {
		return nil, fmt.Errorf("CV-sAPVSS network payload exceeds limit")
	}
	wire := make([]byte, cvNetworkEnvelopeFixedBytesV1+len(sid)+len(payload))
	wire[0] = cvNetworkEnvelopeVersionV1
	offset := 1
	binary.BigEndian.PutUint32(wire[offset:offset+4], uint32(len(sid)))
	offset += 4
	copy(wire[offset:offset+len(sid)], sid)
	offset += len(sid)
	binary.BigEndian.PutUint64(wire[offset:offset+8], uint64(epoch))
	offset += 8
	binary.BigEndian.PutUint32(wire[offset:offset+4], uint32(len(payload)))
	offset += 4
	copy(wire[offset:], payload)
	return wire, nil
}

func cvDecodeNetworkEnvelopeV1(wire []byte, expectedSID string, expectedEpoch int) ([]byte, error) {
	if expectedSID == "" || len(expectedSID) > cvMaxNetworkEnvelopeSIDBytesV1 || expectedEpoch < 0 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS network context")
	}
	maximum := cvNetworkEnvelopeFixedBytesV1 + len(expectedSID) + cvMaxNetworkPayloadBytesV1
	if len(wire) < cvNetworkEnvelopeFixedBytesV1+len(expectedSID) || len(wire) > maximum || wire[0] != cvNetworkEnvelopeVersionV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS network envelope framing")
	}
	offset := 1
	sidLength := int(binary.BigEndian.Uint32(wire[offset : offset+4]))
	offset += 4
	if sidLength != len(expectedSID) || sidLength > len(wire)-offset ||
		!bytes.Equal(wire[offset:offset+sidLength], []byte(expectedSID)) {
		return nil, fmt.Errorf("CV-sAPVSS network envelope SID mismatch")
	}
	offset += sidLength
	if len(wire)-offset < 12 || binary.BigEndian.Uint64(wire[offset:offset+8]) != uint64(expectedEpoch) {
		return nil, fmt.Errorf("CV-sAPVSS network envelope epoch mismatch")
	}
	offset += 8
	payloadLength := int(binary.BigEndian.Uint32(wire[offset : offset+4]))
	offset += 4
	if payloadLength > cvMaxNetworkPayloadBytesV1 || payloadLength != len(wire)-offset {
		return nil, fmt.Errorf("invalid CV-sAPVSS network payload length")
	}
	return append([]byte(nil), wire[offset:]...), nil
}

type cvSAPVSSRouterV1 struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sid      string
	epoch    int
	oldNodes map[int]struct{}
	newNodes map[int]struct{}
	queues   map[int]chan Message
	errors   chan error
	done     chan struct{}
	wait     sync.WaitGroup
	failOnce sync.Once
}

func newCVSAPVSSRouterV1(
	ctx context.Context,
	transport agreementTransport,
	sid string,
	epoch int,
	oldNodes, localOldNodes []int,
	queueCapacity int,
) (*cvSAPVSSRouterV1, error) {
	return newCVSAPVSSRouterWithReceiversV1(
		ctx, transport, sid, epoch, oldNodes, nil, localOldNodes, queueCapacity,
	)
}

func newCVSAPVSSRouterWithReceiversV1(
	ctx context.Context,
	transport agreementTransport,
	sid string,
	epoch int,
	oldNodes, newNodes, localNodes []int,
	queueCapacity int,
) (*cvSAPVSSRouterV1, error) {
	if ctx == nil || transport == nil || sid == "" || len(sid) > cvMaxNetworkEnvelopeSIDBytesV1 ||
		epoch < 0 || queueCapacity <= 0 || len(oldNodes) == 0 || len(localNodes) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS router configuration")
	}
	oldSet := make(map[int]struct{}, len(oldNodes))
	for _, node := range oldNodes {
		if node < 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS old-node ID: %d", node)
		}
		if _, duplicate := oldSet[node]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS old-node ID: %d", node)
		}
		oldSet[node] = struct{}{}
	}
	newSet := make(map[int]struct{}, len(newNodes))
	for _, node := range newNodes {
		if node < 0 {
			return nil, fmt.Errorf("invalid APVSS new-node ID: %d", node)
		}
		if _, duplicate := newSet[node]; duplicate {
			return nil, fmt.Errorf("duplicate APVSS new-node ID: %d", node)
		}
		newSet[node] = struct{}{}
	}
	inboxes := make(map[int]<-chan Message, len(localNodes))
	for _, node := range localNodes {
		_, oldOK := oldSet[node]
		_, newOK := newSet[node]
		if !oldOK && !newOK {
			return nil, fmt.Errorf("local APVSS node %d is outside both rosters", node)
		}
		if _, duplicate := inboxes[node]; duplicate {
			return nil, fmt.Errorf("duplicate local CV-sAPVSS node ID: %d", node)
		}
		inbox, err := transport.RecvChan(node)
		if err != nil {
			return nil, fmt.Errorf("open CV-sAPVSS inbox for node %d: %w", node, err)
		}
		if inbox == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS inbox for node %d", node)
		}
		inboxes[node] = inbox
	}
	routerContext, cancel := context.WithCancel(ctx)
	router := &cvSAPVSSRouterV1{
		ctx:      routerContext,
		cancel:   cancel,
		sid:      sid,
		epoch:    epoch,
		oldNodes: oldSet,
		newNodes: newSet,
		queues:   make(map[int]chan Message, len(inboxes)),
		errors:   make(chan error, 1),
		done:     make(chan struct{}),
	}
	for node, inbox := range inboxes {
		queue := make(chan Message, queueCapacity)
		router.queues[node] = queue
		router.wait.Add(1)
		go router.readLoop(node, inbox, queue)
	}
	go func() {
		router.wait.Wait()
		close(router.errors)
		close(router.done)
	}()
	return router, nil
}

func (r *cvSAPVSSRouterV1) Receive(node int) (<-chan Message, error) {
	queue, ok := r.queues[node]
	if !ok {
		return nil, fmt.Errorf("CV-sAPVSS router has no local node %d", node)
	}
	return queue, nil
}

func (r *cvSAPVSSRouterV1) Errors() <-chan error {
	return r.errors
}

func (r *cvSAPVSSRouterV1) Close() error {
	if r == nil {
		return nil
	}
	r.cancel()
	<-r.done
	return nil
}

func (r *cvSAPVSSRouterV1) readLoop(node int, inbox <-chan Message, queue chan Message) {
	defer r.wait.Done()
	defer close(queue)
	for {
		select {
		case <-r.ctx.Done():
			return
		case msg, ok := <-inbox:
			if !ok {
				if r.ctx.Err() == nil {
					r.fail(fmt.Errorf("CV-sAPVSS transport inbox for node %d closed", node))
				}
				return
			}
			routed, ok := r.route(node, msg)
			if !ok {
				continue
			}
			select {
			case <-r.ctx.Done():
				return
			default:
			}
			select {
			case queue <- routed:
			default:
				r.fail(fmt.Errorf("CV-sAPVSS delivery queue for node %d is full", node))
				return
			}
		}
	}
}

func (r *cvSAPVSSRouterV1) route(node int, msg Message) (Message, bool) {
	if !cvAllowedNetworkTagV1(msg.Tag) || msg.To != node {
		return Message{}, false
	}
	switch msg.Tag {
	case apvssTagLaneOfferV1:
		if _, ok := r.oldNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.newNodes[msg.To]; !ok {
			return Message{}, false
		}
	case apvssTagLaneACKV1:
		if _, ok := r.newNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.oldNodes[msg.To]; !ok {
			return Message{}, false
		}
	default:
		if _, ok := r.oldNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.oldNodes[msg.To]; !ok {
			return Message{}, false
		}
	}
	payload, err := cvDecodeNetworkEnvelopeV1(msg.Body, r.sid, r.epoch)
	if err != nil {
		return Message{}, false
	}
	return Message{From: msg.From, To: msg.To, Tag: msg.Tag, Body: payload}, true
}

func (r *cvSAPVSSRouterV1) fail(err error) {
	r.failOnce.Do(func() {
		r.errors <- err
		r.cancel()
	})
}
