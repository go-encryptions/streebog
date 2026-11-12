// Package streebog implements the GOST R 34.11-2012 hash function (Streebog,
// RFC 6986) with 256-bit and 512-bit digests, in pure Go.
//
// Byte order: RFC 6986 prints every vector big-endian, the most significant
// byte first, so the message of its Example 1 appears as
// 0x3231303938...3130 although it is the string "0123...012". The algorithm
// is defined on integers; implementations (and this package) process the
// message and produce the digest as byte strings with the first byte least
// significant, i.e. the RFC's hexadecimal strings are the byte-reversal of the
// strings that go in and come out of Write and Sum. See the README.
//
// The look-up tables are indexed by secret data, so the package is not
// constant-time.
package streebog

import (
	"encoding/binary"
	"hash"
	"sync"
)

const (
	// Size512 and Size256 are the digest sizes in bytes.
	Size512 = 64
	Size256 = 32
	// BlockSize is the block size in bytes.
	BlockSize = 64
)

var (
	tableOnce sync.Once
	// tab[k][v] is l(Pi(v) << 8k): substitution and the linear map l of the
	// byte v at byte position k of a 64-bit word.
	tab [8][256]uint64
	// cst holds C[1]..C[12] as little-endian words.
	cst [12][8]uint64
)

func buildTables() {
	for k := 0; k < 8; k++ {
		for x := 0; x < 256; x++ {
			// l(w) is the XOR of the rows A[63-i] over the set bits i of w.
			var v uint64
			for j := 0; j < 8; j++ {
				if x>>j&1 == 1 {
					v ^= matrixA[63-(8*k+j)]
				}
			}
			tab[k][x] = v
		}
	}
	// Substitute: tab[k][v] must use Pi(v). The l-tables above are indexed by
	// the substituted byte, so permute them.
	var l [8][256]uint64 = tab
	for k := 0; k < 8; k++ {
		for v := 0; v < 256; v++ {
			tab[k][v] = l[k][pi[v]]
		}
	}
	for i, row := range iterC {
		for c, chunk := range row {
			cst[i][7-c] = chunk
		}
	}
}

// g is the compression function g_N(h, m) = E(LPS(h ^ N), m) ^ h ^ m, with
// E(K, m) = X[K13] LPSX[K12] ... LPSX[K1](m) and K[i] = LPS(K[i-1] ^ C[i-1]).
// The state and the key live in eight locals each (lps8 is lps unrolled).
func g(h, n, m *[8]uint64) [8]uint64 {
	t := &tab
	k0, k1, k2, k3, k4, k5, k6, k7 := lps8(t, h[0]^n[0], h[1]^n[1], h[2]^n[2], h[3]^n[3], h[4]^n[4], h[5]^n[5], h[6]^n[6], h[7]^n[7])
	s0, s1, s2, s3, s4, s5, s6, s7 := m[0]^k0, m[1]^k1, m[2]^k2, m[3]^k3, m[4]^k4, m[5]^k5, m[6]^k6, m[7]^k7
	for i := 0; i < 12; i++ {
		s0, s1, s2, s3, s4, s5, s6, s7 = lps8(t, s0, s1, s2, s3, s4, s5, s6, s7)
		c := &cst[i]
		k0, k1, k2, k3, k4, k5, k6, k7 = lps8(t, k0^c[0], k1^c[1], k2^c[2], k3^c[3], k4^c[4], k5^c[5], k6^c[6], k7^c[7])
		s0, s1, s2, s3, s4, s5, s6, s7 = s0^k0, s1^k1, s2^k2, s3^k3, s4^k4, s5^k5, s6^k6, s7^k7
	}
	return [8]uint64{
		s0 ^ h[0] ^ m[0], s1 ^ h[1] ^ m[1], s2 ^ h[2] ^ m[2], s3 ^ h[3] ^ m[3],
		s4 ^ h[4] ^ m[4], s5 ^ h[5] ^ m[5], s6 ^ h[6] ^ m[6], s7 ^ h[7] ^ m[7],
	}
}

// add512 adds b to a modulo 2^512.
func add512(a, b *[8]uint64) {
	var carry uint64
	for i := range a {
		s := a[i] + b[i]
		c1 := uint64(0)
		if s < a[i] {
			c1 = 1
		}
		s2 := s + carry
		if s2 < s {
			c1 = 1
		}
		a[i] = s2
		carry = c1
	}
}

type digest struct {
	h, n, sigma [8]uint64
	buf         [BlockSize]byte
	nbuf        int
	size        int
}

func newDigest(size int) *digest {
	tableOnce.Do(buildTables)
	d := &digest{size: size}
	d.Reset()
	return d
}

// New512 returns a hash.Hash computing the 512-bit GOST R 34.11-2012 digest.
func New512() hash.Hash { return newDigest(Size512) }

// New256 returns a hash.Hash computing the 256-bit GOST R 34.11-2012 digest.
func New256() hash.Hash { return newDigest(Size256) }

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	d.h = [8]uint64{}
	if d.size == Size256 {
		for i := range d.h {
			d.h[i] = 0x0101010101010101
		}
	}
	d.n = [8]uint64{}
	d.sigma = [8]uint64{}
	d.nbuf = 0
}

func loadBlock(b []byte) (m [8]uint64) {
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	return m
}

// block processes one full block: steps 2.3 to 2.5 of RFC 6986.
func (d *digest) block(b []byte) {
	m := loadBlock(b)
	d.h = g(&d.h, &d.n, &m)
	add512(&d.n, &[8]uint64{512})
	add512(&d.sigma, &m)
}

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	if d.nbuf > 0 {
		k := copy(d.buf[d.nbuf:], p)
		d.nbuf += k
		p = p[k:]
		if d.nbuf < BlockSize {
			return n, nil
		}
		d.block(d.buf[:])
		d.nbuf = 0
	}
	for len(p) >= BlockSize {
		d.block(p[:BlockSize])
		p = p[BlockSize:]
	}
	d.nbuf = copy(d.buf[:], p)
	return n, nil
}

// Sum appends the digest of the data written so far to b without changing the
// state: step 3 of RFC 6986 on a copy.
func (d *digest) Sum(b []byte) []byte {
	e := *d
	var last [BlockSize]byte
	copy(last[:], e.buf[:e.nbuf])
	last[e.nbuf] = 1
	m := loadBlock(last[:])
	e.h = g(&e.h, &e.n, &m)
	add512(&e.n, &[8]uint64{uint64(e.nbuf) * 8})
	add512(&e.sigma, &m)
	var zero [8]uint64
	e.h = g(&e.h, &zero, &e.n)
	e.h = g(&e.h, &zero, &e.sigma)
	words := e.h[:]
	if d.size == Size256 {
		words = e.h[4:] // MSB_256
	}
	for _, w := range words {
		b = binary.LittleEndian.AppendUint64(b, w)
	}
	return b
}

// Sum512 returns the 512-bit digest of data.
func Sum512(data []byte) [Size512]byte {
	d := newDigest(Size512)
	d.Write(data)
	var out [Size512]byte
	d.Sum(out[:0])
	return out
}

// Sum256 returns the 256-bit digest of data.
func Sum256(data []byte) [Size256]byte {
	d := newDigest(Size256)
	d.Write(data)
	var out [Size256]byte
	d.Sum(out[:0])
	return out
}
