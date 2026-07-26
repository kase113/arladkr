package core

import (
	"bytes"
	"context"
	"encoding/gob"
	"strings"
	"testing"

	dmvba "dumbomvba_go/core"
)

func TestArladkrMVBAWireGobRoundTripWithNestedProtocolBodies(t *testing.T) {
	wire := arladkrMVBAWire{
		From: 2,
		Msg: dmvba.ProtocolMessage{
			Tag:    dmvba.TagACSDiffuse,
			Round:  3,
			Leader: 1,
			Body: struct {
				SID string
			}{
				SID: "placeholder",
			},
		},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wire); err == nil {
		t.Fatalf("expected gob encode to fail for unregistered body type")
	}
}

func TestArladkrMVBAWireGobRoundTripWithRealMVBAProposalBody(t *testing.T) {
	wire := arladkrMVBAWire{
		From: 1,
		Msg: dmvba.ProtocolMessage{
			Tag:    dmvba.TagACSDiffuse,
			Round:  0,
			Leader: 0,
			Body: dmvba.ProposalValue{
				Payload: []byte("payload"),
				Round:   7,
				Hint:    "hint",
			},
		},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wire); err != nil {
		t.Fatalf("gob encode failed: %v", err)
	}

	var out arladkrMVBAWire
	if err := gob.NewDecoder(&buf).Decode(&out); err != nil {
		t.Fatalf("gob decode failed: %v", err)
	}
	body, ok := out.Msg.Body.(dmvba.ProposalValue)
	if !ok {
		t.Fatalf("decoded body type mismatch: %T", out.Msg.Body)
	}
	if string(body.Payload) != "payload" || body.Round != 7 || body.Hint != "hint" {
		t.Fatalf("decoded proposal mismatch: %+v", body)
	}
}

func TestSelectAgreedPayloadsAppliesPredicateAndPreservesProposerOrder(t *testing.T) {
	vec := []*dmvba.ProposalValue{
		{Payload: []byte("bad"), Round: 1, Hint: "cv-component-candidate"},
		nil,
		{Payload: []byte("two"), Round: 1, Hint: "cv-component-candidate"},
		{Payload: []byte("wrong-round"), Round: 2, Hint: "cv-component-candidate"},
		{Payload: []byte("wrong-hint"), Round: 1, Hint: "other-instance"},
		{Payload: []byte("five"), Round: 1, Hint: "cv-component-candidate"},
	}
	got := selectAgreedPayloads(vec, 1, "cv-component-candidate", func(_ int, payload []byte) bool {
		return string(payload) != "bad"
	})
	if len(got) != 2 || string(got[0]) != "two" || string(got[1]) != "five" {
		t.Fatalf("unexpected predicate-filtered vector: %q", got)
	}
}

func TestArladkrMVBAInstanceDomainsAreDistinct(t *testing.T) {
	component, err := arlMVBAInstanceSID("sid", "cv-component-candidate")
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := arlMVBAInstanceSID("sid", "cv-materialized-aggrlo")
	if err != nil {
		t.Fatal(err)
	}
	if component == aggregate || !strings.Contains(component, "cv-component-candidate") ||
		!strings.Contains(aggregate, "cv-materialized-aggrlo") {
		t.Fatalf("MVBA instance domains are not distinct: %q / %q", component, aggregate)
	}
}

func TestPredicateBearingMVBATCPRequiresOneLocalOldNode(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "mvba-predicate-local-node",
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{4, 5, 6, 7},
		FOld:         1,
		FNew:         1,
		LocalNodeIDs: []int{0, 1},
	})
	_, _, err := runArladkrMVBATCPInstance(
		context.Background(), cfg, "cv-component-candidate", []byte("candidate"),
		func(_ int, _ []byte) bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "exactly one local old node") {
		t.Fatalf("predicate-bearing MVBA accepted multiple local old nodes: %v", err)
	}
}

func TestArladkrTCPNetBroadcastPropagatesSendError(t *testing.T) {
	neti := &arladkrTCPNet{
		id: 0,
		hub: &arladkrTCPHub{
			addrByID: map[int]string{
				0: "127.0.0.1:1",
				1: "127.0.0.1:1",
			},
			dialTO:  10,
			retries: 1,
			backoff: 1,
		},
	}

	err := neti.Broadcast(dmvba.ProtocolMessage{Tag: dmvba.TagACSDiffuse})
	if err == nil {
		t.Fatalf("expected broadcast to propagate send error")
	}
}
