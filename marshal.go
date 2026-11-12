package streebog

import (
	"encoding/binary"
	"errors"
	"hash"
)

// The state is serialised as a magic that names the digest size, the chaining
// value h, the bit counter N and the checksum EPSILON (eight little-endian
// words each), the 64-byte block buffer (bytes past the buffered count are
// zero) and the buffered count as one byte.
const (
	magic256      = "stb\x02"
	magic512      = "stb\x05"
	marshaledSize = 4 + 3*64 + BlockSize + 1
)

var (
	errShort = errors.New("streebog: state has the wrong length")
	errMagic = errors.New("streebog: not a state of this digest size")
	errState = errors.New("streebog: inconsistent state")
)

func (d *digest) magic() string {
	if d.size == Size256 {
		return magic256
	}
	return magic512
}

// MarshalBinary implements encoding.BinaryMarshaler. crypto/hmac and
// crypto/pbkdf2 use it to keep the keyed states of HMAC instead of
// recomputing them.
func (d *digest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, marshaledSize))
}

// AppendBinary implements encoding.BinaryAppender.
func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, d.magic()...)
	for _, v := range [...]*[8]uint64{&d.h, &d.n, &d.sigma} {
		for _, w := range v {
			b = binary.LittleEndian.AppendUint64(b, w)
		}
	}
	b = append(b, d.buf[:d.nbuf]...)
	b = append(b, make([]byte, BlockSize-d.nbuf)...)
	return append(b, byte(d.nbuf)), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler. It refuses a state of
// the wrong length, the magic of the other digest size or a foreign one, and a
// buffer that disagrees with its count, and leaves the receiver unchanged in
// that case.
func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) != marshaledSize {
		return errShort
	}
	if string(b[:4]) != d.magic() {
		return errMagic
	}
	b = b[4:]
	e := digest{size: d.size}
	for _, v := range [...]*[8]uint64{&e.h, &e.n, &e.sigma} {
		for i := range v {
			v[i] = binary.LittleEndian.Uint64(b)
			b = b[8:]
		}
	}
	buf := b[:BlockSize]
	// N counts whole processed blocks, in bits: a multiple of 512.
	if b[BlockSize] >= BlockSize || e.n[0]&511 != 0 {
		return errState
	}
	e.nbuf = int(b[BlockSize])
	for _, x := range buf[e.nbuf:] {
		if x != 0 {
			return errState
		}
	}
	copy(e.buf[:], buf[:e.nbuf])
	*d = e
	return nil
}

// Clone implements hash.Cloner: an independent copy of the running state.
func (d *digest) Clone() (hash.Cloner, error) {
	c := *d
	return &c, nil
}
