package core

import "fmt"

func UpdateAndEraseReceiverStates(
	cfg Config,
	current map[int]ReceiverState,
	contextDigest []byte,
	eraseBuffers ...[]byte,
) (map[int]ReceiverState, error) {
	out := make(map[int]ReceiverState, len(cfg.NewCommittee))
	for _, id := range cfg.NewCommittee {
		var st ReceiverState
		if current != nil {
			if v, ok := current[id]; ok {
				st = cloneReceiverState(v)
			}
		}
		if len(st.SecretKey) == 0 || len(st.PublicKey) == 0 {
			if cfg.Epoch > 1 {
				return nil, fmt.Errorf("missing receiver state for id=%d epoch=%d", id, cfg.Epoch)
			}
			var err error
			st, err = rfsInitState(cfg, id)
			if err != nil {
				return nil, err
			}
		}
		if st.NodeID != id {
			st.NodeID = id
		}
		next, old, err := rfsUpdateState(cfg, st, id, contextDigest)
		if err != nil {
			return nil, err
		}
		rfsErase(&old)
		if current != nil {
			wiped := cloneReceiverState(st)
			rfsErase(&wiped)
			current[id] = wiped
		}
		out[id] = next
	}
	for _, b := range eraseBuffers {
		zeroBytes(b)
	}
	return out, nil
}
