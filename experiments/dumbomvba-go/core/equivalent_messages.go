package core

type EquivalentMessageClass string

const (
	EquivalentMessageOther       EquivalentMessageClass = ""
	EquivalentMessagePDData      EquivalentMessageClass = "pd_data"
	EquivalentMessageRCData      EquivalentMessageClass = "rc_data"
	EquivalentMessageCertificate EquivalentMessageClass = "certificate"
)

// ClassifyEquivalentMessage exposes only the wire-cost category needed by
// experiment instrumentation; equivalent protocol body types remain private.
func ClassifyEquivalentMessage(msg ProtocolMessage) EquivalentMessageClass {
	switch body := msg.Body.(type) {
	case pdStoreMsg:
		return EquivalentMessagePDData
	case rcStoreMsg:
		return EquivalentMessageRCData
	case pdLockMsg, pdDoneMsg, quitFinishMsg, rcLockMsg:
		return EquivalentMessageCertificate
	case rcPrepareMsg:
		if body.Lock != nil {
			return EquivalentMessageCertificate
		}
	}
	return EquivalentMessageOther
}

type merkleBranch struct {
	Index    int
	Siblings [][]byte
}

type pdStoreMsg struct {
	SID    string
	Root   []byte
	Stripe []byte
	Branch merkleBranch
}

type pdStoredMsg struct {
	SID   string
	Root  []byte
	Share []byte
}

type pdLockMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type pdLockedMsg struct {
	SID   string
	Root  []byte
	Share []byte
}

type pdDoneMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type quitReadyMsg struct {
	SID   string
	Share []byte
}

type quitFinishMsg struct {
	SID         string
	Certificate []byte
}

type rcStoreMsg struct {
	SID    string
	Root   []byte
	From   int
	Stripe []byte
	Branch merkleBranch
}

type rcLockMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type rcPrepareMsg struct {
	SID    string
	Leader int
	Lock   *pdLockMsg
}

type coinShareMsg struct {
	SID   string
	Nonce string
	Share []byte
}

type abaEstMsg struct {
	SID   string
	Iter  int
	Value int
}

type abaDecisionMsg struct {
	SID   string
	Iter  int
	Value int
}

type acsDiffuseMsg struct {
	SID   string
	Value ProposalValue
	Sig   []byte
}

type acsVectorEntry struct {
	From  int
	Value ProposalValue
	Sig   []byte
}
