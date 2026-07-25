package core

import "crypto/cipher"

type deterministicReader struct {
	stream cipher.Stream
}

func newDeterministicReader(stream cipher.Stream) *deterministicReader {
	return &deterministicReader{stream: stream}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	zeros := make([]byte, len(p))
	r.stream.XORKeyStream(p, zeros)
	return len(p), nil
}
