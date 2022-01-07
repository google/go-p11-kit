package rpc

type buffer struct {
	b []byte
}

func (b *buffer) Bytes() []byte {
	return b.b
}

func newBuffer(b []byte) *buffer {
	return &buffer{b: b}
}

func (b *buffer) addByteArray(a []byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L730
	b.addUint32(uint32(len(a)))
	b.b = append(b.b, a...)
}

func (b *buffer) addUint32(n uint32) {
	var buff [4]byte
	binaryEncoding.PutUint32(buff[:], n)
	b.b = append(b.b, buff[:]...)
}

func (b *buffer) addUint64(n uint64) {
	var buff [8]byte
	binaryEncoding.PutUint64(buff[:], n)
	b.b = append(b.b, buff[:]...)
}

func (b *buffer) addByte(by byte) {
	b.b = append(b.b, by)
}

func (b *buffer) byte(by *byte) bool {
	if len(b.b) == 0 {
		return false
	}
	*by = b.b[0]
	b.b = b.b[1:]
	return true
}

func (b *buffer) uint32(n *uint32) bool {
	if len(b.b) < 4 {
		return false
	}
	buff := b.b[:4]
	b.b = b.b[4:]
	*n = binaryEncoding.Uint32(buff)
	return true
}

func (b *buffer) uint64(n *uint64) bool {
	if len(b.b) < 8 {
		return false
	}
	buff := b.b[:8]
	b.b = b.b[8:]
	*n = binaryEncoding.Uint64(buff)
	return true
}

func (b *buffer) byteArray(a *[]byte) bool {
	var n uint32
	if !b.uint32(&n) {
		return false
	}
	if len(b.b) < int(n) {
		return false
	}
	*a = b.b[:n]
	b.b = b.b[n:]
	return true
}
