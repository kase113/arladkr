package core

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
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

func TestSelectAgreedPayloadChoosesFirstNonEmptyVectorEntry(t *testing.T) {
	wantPayload, err := json.Marshal("digest-hex")
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}
	vec := []*dmvba.ProposalValue{
		nil,
		{Payload: wantPayload, Round: 0, Hint: "acs-vacs"},
	}

	got := selectAgreedPayload(vec)
	if !bytes.Equal(got, wantPayload) {
		t.Fatalf("unexpected selected payload: got=%q want=%q", got, wantPayload)
	}
}

func TestSelectAgreedPayloadsAppliesPredicateAndPreservesProposerOrder(t *testing.T) {
	vec := []*dmvba.ProposalValue{
		{Payload: []byte("bad"), Round: 1, Hint: "cv-component-candidate-v1"},
		nil,
		{Payload: []byte("two"), Round: 1, Hint: "cv-component-candidate-v1"},
		{Payload: []byte("wrong-round"), Round: 2, Hint: "cv-component-candidate-v1"},
		{Payload: []byte("wrong-hint"), Round: 1, Hint: "other-instance"},
		{Payload: []byte("five"), Round: 1, Hint: "cv-component-candidate-v1"},
	}
	got := selectAgreedPayloads(vec, 1, "cv-component-candidate-v1", func(_ int, payload []byte) bool {
		return string(payload) != "bad"
	})
	if len(got) != 2 || string(got[0]) != "two" || string(got[1]) != "five" {
		t.Fatalf("unexpected predicate-filtered vector: %q", got)
	}
}

func TestArladkrMVBAInstanceDomainsAreDistinct(t *testing.T) {
	component, err := arlMVBAInstanceSID("sid", "cv-component-candidate-v1", false)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := arlMVBAInstanceSID("sid", "cv-materialized-aggrlo-v1", false)
	if err != nil {
		t.Fatal(err)
	}
	if component == aggregate || !strings.Contains(component, "cv-component-candidate-v1") ||
		!strings.Contains(aggregate, "cv-materialized-aggrlo-v1") {
		t.Fatalf("MVBA instance domains are not distinct: %q / %q", component, aggregate)
	}
}

func TestPredicateBearingMVBATCPRejectsDirectKernel(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:             "mvba-predicate-direct",
		OldCommittee:    []int{0, 1, 2, 3},
		NewCommittee:    []int{4, 5, 6, 7},
		FOld:            1,
		FNew:            1,
		AgreementKernel: "dumbomvba-direct",
	})
	_, _, err := runArladkrMVBATCPInstance(
		context.Background(), cfg, "cv-component-candidate-v1", []byte("candidate"),
		func(_ int, _ []byte) bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "external predicate") {
		t.Fatalf("predicate-bearing direct MVBA was not rejected: %v", err)
	}
}

func TestPredicateBearingMVBATCPRequiresOneLocalOldNode(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:             "mvba-predicate-local-node",
		OldCommittee:    []int{0, 1, 2, 3},
		NewCommittee:    []int{4, 5, 6, 7},
		FOld:            1,
		FNew:            1,
		AgreementKernel: "commonsubset-tcp",
		LocalNodeIDs:    []int{0, 1},
	})
	_, _, err := runArladkrMVBATCPInstance(
		context.Background(), cfg, "cv-component-candidate-v1", []byte("candidate"),
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
