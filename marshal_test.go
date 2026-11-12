package streebog

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"encoding"
	"hash"
	"testing"
)

type state interface {
	hash.Cloner
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.BinaryAppender
}

var sizes = []struct {
	name string
	mk   func() hash.Hash
}{{"512", New512}, {"256", New256}}

func TestInterfaces(t *testing.T) {
	for _, s := range sizes {
		if _, ok := s.mk().(state); !ok {
			t.Fatalf("%s: digest does not implement the marshalling interfaces", s.name)
		}
	}
}

// A state saved after n bytes, restored into a fresh hash, must go on exactly
// like the original: every buffer fill from 0 to two blocks and a bit.
func TestMarshalRoundTrip(t *testing.T) {
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i*11 + 3)
	}
	for _, s := range sizes {
		for n := 0; n <= 130; n++ {
			a := s.mk()
			a.Write(data[:n])
			saved, err := a.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil || len(saved) != marshaledSize {
				t.Fatalf("%s n=%d: %d bytes, %v", s.name, n, len(saved), err)
			}
			b := s.mk()
			if err := b.(encoding.BinaryUnmarshaler).UnmarshalBinary(saved); err != nil {
				t.Fatalf("%s n=%d: %v", s.name, n, err)
			}
			if !bytes.Equal(a.Sum(nil), b.Sum(nil)) {
				t.Fatalf("%s n=%d: digests differ right after restore", s.name, n)
			}
			a.Write(data[n:])
			b.Write(data[n:])
			c := s.mk()
			c.Write(data)
			if !bytes.Equal(b.Sum(nil), c.Sum(nil)) || !bytes.Equal(a.Sum(nil), c.Sum(nil)) {
				t.Fatalf("%s n=%d: restored hash disagrees with one-shot", s.name, n)
			}
			again, _ := b.(encoding.BinaryAppender).AppendBinary([]byte("x"))
			if again[0] != 'x' || len(again) != 1+marshaledSize {
				t.Fatalf("%s n=%d: AppendBinary", s.name, n)
			}
		}
	}
}

func TestUnmarshalRefuses(t *testing.T) {
	h := New512()
	h.Write([]byte("abc"))
	good, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	mutate := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	cases := map[string][]byte{
		"empty":                   nil,
		"short":                   good[:len(good)-1],
		"long":                    append(bytes.Clone(good), 0),
		"foreign magic":           mutate(func(b []byte) []byte { b[0] = 'x'; return b }),
		"dirty padding":           mutate(func(b []byte) []byte { b[len(b)-2] = 1; return b }),
		"count too big":           mutate(func(b []byte) []byte { b[len(b)-1] = 64; return b }),
		"N not a multiple of 512": mutate(func(b []byte) []byte { b[4+64] = 1; return b }),
		"N off by one bit":        mutate(func(b []byte) []byte { b[4+64+1] = 0x01; b[4+64] = 0xff; return b }),
		"count too low":           mutate(func(b []byte) []byte { b[len(b)-1] = 2; return b }),
	}
	for name, b := range cases {
		d := New512()
		d.Write([]byte("keep"))
		before := d.Sum(nil)
		if err := d.(encoding.BinaryUnmarshaler).UnmarshalBinary(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !bytes.Equal(before, d.Sum(nil)) {
			t.Errorf("%s: a refused state changed the receiver", name)
		}
	}
	// A 512-bit state is not a 256-bit state and the other way round.
	if err := New256().(encoding.BinaryUnmarshaler).UnmarshalBinary(good); err == nil {
		t.Error("512-bit state accepted by a 256-bit hash")
	}
	h2 := New256()
	g2, _ := h2.(encoding.BinaryMarshaler).MarshalBinary()
	if err := New512().(encoding.BinaryUnmarshaler).UnmarshalBinary(g2); err == nil {
		t.Error("256-bit state accepted by a 512-bit hash")
	}
}

func TestClone(t *testing.T) {
	for _, s := range sizes {
		a := s.mk()
		a.Write([]byte("abc"))
		c, err := a.(hash.Cloner).Clone()
		if err != nil {
			t.Fatal(err)
		}
		a.Write([]byte("def"))
		x := s.mk()
		x.Write([]byte("abc"))
		if !bytes.Equal(c.Sum(nil), x.Sum(nil)) {
			t.Fatalf("%s: the clone followed the original", s.name)
		}
		c.Write([]byte("xyz"))
		y := s.mk()
		y.Write([]byte("abcdef"))
		if !bytes.Equal(a.Sum(nil), y.Sum(nil)) {
			t.Fatalf("%s: the original followed the clone", s.name)
		}
	}
}

// plain hides the marshalling methods, so crypto/hmac recomputes the keyed
// states instead of restoring them. Both paths must give the same bytes.
type plain struct{ hash.Hash }

func TestHMACAndPBKDF2WithAndWithoutMarshalling(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 100) // longer than a block: hashed first
	msg := []byte("Hi There")
	for _, s := range sizes {
		mk := s.mk
		fast, slow := hmac.New(mk, key), hmac.New(func() hash.Hash { return plain{mk()} }, key)
		for i := 0; i < 3; i++ {
			fast.Write(msg)
			slow.Write(msg)
			if !bytes.Equal(fast.Sum(nil), slow.Sum(nil)) {
				t.Fatalf("%s: HMAC differs on pass %d", s.name, i)
			}
			fast.Reset()
			slow.Reset()
		}
		a, err := pbkdf2.Key(mk, "password", []byte("salt"), 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		b, err := pbkdf2.Key(func() hash.Hash { return plain{mk()} }, "password", []byte("salt"), 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: PBKDF2 differs", s.name)
		}
	}
}

func FuzzUnmarshalBinary(f *testing.F) {
	for _, s := range sizes {
		h := s.mk()
		h.Write([]byte("seed"))
		good, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
		f.Add(good, s.name == "256")
	}
	f.Add([]byte(magic512), false)
	f.Fuzz(func(t *testing.T, b []byte, is256 bool) {
		d := New512()
		if is256 {
			d = New256()
		}
		if err := d.(encoding.BinaryUnmarshaler).UnmarshalBinary(b); err != nil {
			return
		}
		// An accepted state is canonical: it marshals back to the same bytes
		// and hashing on from it does not panic.
		again, _ := d.(encoding.BinaryMarshaler).MarshalBinary()
		if !bytes.Equal(again, b) {
			t.Fatalf("accepted state does not round-trip")
		}
		d.Write([]byte("more"))
		d.Sum(nil)
	})
}
