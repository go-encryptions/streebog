package streebog

import (
	"bytes"
	"encoding/hex"
	"hash"
	"os"
	"strings"
	"testing"
)

type vector struct {
	section string
	in, out []byte
}

// readVec parses the Botan test-vector format: [Section] lines, "In = hex" and
// "Out = hex" pairs, '#' comments; the input may be empty.
func readVec(t testing.TB, path string) []vector {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	var in []byte
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "["):
			section = strings.Trim(line, "[]")
		case strings.HasPrefix(line, "In ="):
			in, err = hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "In =")))
			if err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(line, "Out ="):
			out, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "Out =")))
			if err != nil {
				t.Fatal(err)
			}
			vs = append(vs, vector{section, in, out})
		}
	}
	return vs
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// rev reverses a byte string: RFC 6986 prints vectors most significant byte
// first, while the message and digest byte strings of this package (and of
// Botan, whose streebog.vec was opened) have the least significant first. That
// VeraCrypt uses the same order is to be pinned by go-fde/veracrypt's
// known-answer test.
func rev(b []byte) []byte {
	r := make([]byte, len(b))
	for i, x := range b {
		r[len(b)-1-i] = x
	}
	return r
}

// RFC 6986 section 10, exactly as printed there (big-endian).
const (
	rfcM1 = "32313039383736353433323130393837 36353433323130393837363534333231 30393837363534333231303938373635 343332313039383736353433323130"
	rfcM2 = "fbe2e5f0eee3c820fbeafaebef20fffb f0e1e0f0f520e0ed20e8ece0ebe5f0f2 f120fff0eeec20f120faf2fee5e2202c e8f6f3ede220e8e6eee1e8f0f2d1202c e8f0f2e5e220e5d1"

	rfcH512M1 = "486f64c1917879417fef082b3381a4e2 11c324f074654c38823a7b76f830ad00 fa1fbae42b1285c0352f227524bc9ab1 6254288dd6863dccd5b9f54a1ad0541b"
	rfcH256M1 = "00557be5e584fd52a449b16b0251d05d 27f94ab76cbaa6da890b59d8ef1e159d"
	rfcH512M2 = "28fbc9bada033b1460642bdcddb90c3f b3e56c497ccd0f62b8a2ad4935e85f03 7613966de4ee00531ae60f3b5a47f8da e06915d5f2f194996fcabf2622e6881e"
	rfcH256M2 = "508f7e553c06501d749a66fc28c6cac0 b005746d97537fa85d9e40904efed29d"
)

func TestRFC6986(t *testing.T) {
	for _, c := range []struct {
		name, msg, h512, h256 string
	}{
		{"M1", rfcM1, rfcH512M1, rfcH256M1},
		{"M2", rfcM2, rfcH512M2, rfcH256M2},
	} {
		// The RFC's string reversed is the byte string the API takes.
		msg := rev(unhex(c.msg))
		if got := Sum512(msg); !bytes.Equal(got[:], rev(unhex(c.h512))) {
			t.Errorf("%s 512: %x, want %x", c.name, got, rev(unhex(c.h512)))
		}
		if got := Sum256(msg); !bytes.Equal(got[:], rev(unhex(c.h256))) {
			t.Errorf("%s 256: %x, want %x", c.name, got, rev(unhex(c.h256)))
		}
	}
	// M1 is the 63-byte string "012345678901234567890123456789012345678901234567890123456789012".
	m1 := []byte("012345678901234567890123456789012345678901234567890123456789012")
	if !bytes.Equal(rev(unhex(rfcM1)), m1) {
		t.Fatal("M1 is not the digit string")
	}
}

func checkVectors(t *testing.T, path string, atLeast int) {
	vs := readVec(t, path)
	if len(vs) < atLeast {
		t.Fatalf("%s: %d vectors, want at least %d", path, len(vs), atLeast)
	}
	for i, v := range vs {
		var mk func() hash.Hash
		switch v.section {
		case "Streebog-256":
			mk = New256
		case "Streebog-512":
			mk = New512
		default:
			t.Fatalf("%s: unknown section %q", path, v.section)
		}
		h := mk()
		h.Write(v.in)
		if got := h.Sum(nil); !bytes.Equal(got, v.out) {
			t.Errorf("%s %s #%d (%d bytes): %x, want %x", path, v.section, i, len(v.in), got, v.out)
		}
		// The same input fed in uneven pieces must agree.
		h.Reset()
		for off, step := 0, 1; off < len(v.in); off, step = off+step, step%67+1 {
			h.Write(v.in[off:min(off+step, len(v.in))])
		}
		if got := h.Sum(nil); !bytes.Equal(got, v.out) {
			t.Errorf("%s %s #%d chunked: %x, want %x", path, v.section, i, got, v.out)
		}
	}
}

func TestBotanVectors(t *testing.T) { checkVectors(t, "testdata/botan-streebog.vec", 20) }
func TestBotanDiff(t *testing.T)    { checkVectors(t, "testdata/botan-diff.vec", 1000) }

func TestHashContract(t *testing.T) {
	for _, c := range []struct {
		name string
		mk   func() hash.Hash
		size int
		sum  func([]byte) []byte
	}{
		{"512", New512, 64, func(b []byte) []byte { s := Sum512(b); return s[:] }},
		{"256", New256, 32, func(b []byte) []byte { s := Sum256(b); return s[:] }},
	} {
		h := c.mk()
		if h.Size() != c.size || h.BlockSize() != 64 {
			t.Fatalf("%s: Size or BlockSize", c.name)
		}
		h.Write([]byte("abc"))
		first := h.Sum([]byte("prefix"))
		if !bytes.HasPrefix(first, []byte("prefix")) || len(first) != 6+c.size {
			t.Fatalf("%s: Sum must append", c.name)
		}
		if second := h.Sum([]byte("prefix")); !bytes.Equal(first, second) {
			t.Fatalf("%s: Sum changed the state", c.name)
		}
		h.Write([]byte("def"))
		if got := h.Sum(nil); !bytes.Equal(got, c.sum([]byte("abcdef"))) {
			t.Fatalf("%s: writing after Sum", c.name)
		}
		h.Reset()
		h.Write([]byte("abc"))
		if got := h.Sum(nil); !bytes.Equal(got, c.sum([]byte("abc"))) {
			t.Fatalf("%s: Reset", c.name)
		}
	}
}

// Every length around the block boundary agrees between one-shot and
// byte-by-byte writes.
func TestBoundaries(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i * 7)
	}
	for n := 0; n <= len(data); n++ {
		want := Sum512(data[:n])
		h := New512()
		for i := 0; i < n; i++ {
			h.Write(data[i : i+1])
		}
		if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
			t.Fatalf("length %d: bytewise %x, one-shot %x", n, got, want)
		}
	}
}

func TestAdd512Carry(t *testing.T) {
	a := [8]uint64{^uint64(0), ^uint64(0), 5}
	add512(&a, &[8]uint64{1})
	if a != [8]uint64{0, 0, 6} {
		t.Fatalf("carry chain: %x", a)
	}
	// Both the addition and the incoming carry overflow.
	b := [8]uint64{^uint64(0), ^uint64(0), 0}
	add512(&b, &[8]uint64{^uint64(0), 0, 0})
	if b != [8]uint64{^uint64(0) - 1, 0, 1} {
		t.Fatalf("carry: %x", b)
	}
	// Wraps modulo 2^512.
	c := [8]uint64{7: ^uint64(0)}
	add512(&c, &[8]uint64{7: 2})
	if c != [8]uint64{7: 1} {
		t.Fatalf("wrap: %x", c)
	}
}

// refLPS is LPS written straight from RFC 6986 sections 6.3, 6.4 and 7 on a
// byte string (byte 0 least significant): S byte by byte, P by Tau, L bit by
// bit over the matrix rows. It is the oracle for the table-driven lps8.
func refLPS(a [64]byte) [64]byte {
	var s, p, r [64]byte
	for i, v := range a {
		s[i] = pi[v]
	}
	for i := range p {
		p[i] = s[(i%8)*8+i/8] // Tau(i)
	}
	for w := 0; w < 8; w++ {
		x := uint64(0)
		for b := 0; b < 8; b++ {
			x |= uint64(p[8*w+b]) << (8 * b)
		}
		var l uint64
		for i := 0; i < 64; i++ { // bit i of x selects row 63-i
			if x>>i&1 == 1 {
				l ^= matrixA[63-i]
			}
		}
		for b := 0; b < 8; b++ {
			r[8*w+b] = byte(l >> (8 * b))
		}
	}
	return r
}

func TestLPSMatchesReference(t *testing.T) {
	newDigest(Size512)
	var a [64]byte
	for round := 0; round < 40; round++ {
		for i := range a {
			a[i] = byte(i*31 + round*17 + i*i)
		}
		w := loadBlock(a[:])
		r0, r1, r2, r3, r4, r5, r6, r7 := lps8(&tab, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7])
		got := [8]uint64{r0, r1, r2, r3, r4, r5, r6, r7}
		want := loadBlock(func() []byte { x := refLPS(a); return x[:] }())
		if got != want {
			t.Fatalf("round %d: lps8 %x, reference %x", round, got, want)
		}
	}
}

func TestPiIsPermutation(t *testing.T) {
	var seen [256]bool
	for _, v := range pi {
		seen[v] = true
	}
	for v, ok := range seen {
		if !ok {
			t.Fatalf("Pi misses %d", v)
		}
	}
}

func FuzzChunking(f *testing.F) {
	f.Add([]byte(""), uint8(1))
	f.Add([]byte("abc"), uint8(2))
	f.Add(bytes.Repeat([]byte{0xff}, 130), uint8(63))
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		want512, want256 := Sum512(data), Sum256(data)
		h5, h2 := New512(), New256()
		s := int(step)%70 + 1
		for off := 0; off < len(data); off += s {
			e := min(off+s, len(data))
			h5.Write(data[off:e])
			h2.Write(data[off:e])
		}
		if got := h5.Sum(nil); !bytes.Equal(got, want512[:]) {
			t.Fatalf("512 chunk %d: %x vs %x", s, got, want512)
		}
		if got := h2.Sum(nil); !bytes.Equal(got, want256[:]) {
			t.Fatalf("256 chunk %d: %x vs %x", s, got, want256)
		}
		if !bytes.Equal(h5.Sum(nil), h5.Sum(nil)) {
			t.Fatal("Sum is not idempotent")
		}
	})
}
