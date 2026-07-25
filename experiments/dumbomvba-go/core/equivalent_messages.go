package core

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
	SID   string
	Root  []byte
	Proof []SigShare
}

type pdLockedMsg struct {
	SID   string
	Root  []byte
	Share []byte
}

type pdDoneMsg struct {
	SID   string
	Root  []byte
	Proof []SigShare
}

type quitReadyMsg struct {
	SID   string
	Share []byte
}

type quitFinishMsg struct {
	SID   string
	Proof []SigShare
}

type rcStoreMsg struct {
	SID    string
	Root   []byte
	From   int
	Stripe []byte
	Branch merkleBranch
}

type rcLockMsg struct {
	SID   string
	Root  []byte
	Proof []SigShare
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
