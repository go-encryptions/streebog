package streebog

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"testing"
)

// RFC 7836 section 4.1 defines HMAC_GOSTR3411_2012_256 and _512 as RFC 2104
// HMAC over H_256 and H_512 (B = 64), and its Appendix B gives the test
// examples. They are octet strings as printed, in the byte-string order of
// this package: key 00 01 ... 1f, and T below, hashed as is. An independent
// oracle for the marshalling path of crypto/hmac.
func TestHMACRFC7836(t *testing.T) {
	key := unhex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f")
	msg := unhex("01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00")
	for _, c := range []struct {
		name string
		mk   func() hash.Hash
		want string
	}{
		{"256", New256, "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"},
		{"512", New512, "a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8 54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77 " +
			"3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f 3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6"},
	} {
		want := unhex(c.want)
		mk := c.mk
		// With the marshalling path (keyed states saved) and without it.
		for _, m := range []struct {
			name string
			mk   func() hash.Hash
		}{{"marshalling", mk}, {"plain", func() hash.Hash { return plain{mk()} }}} {
			h := hmac.New(m.mk, key)
			for pass := 0; pass < 2; pass++ { // Reset restores the saved states
				h.Write(msg)
				if got := h.Sum(nil); !bytes.Equal(got, want) {
					t.Errorf("%s %s pass %d: %x, want %x", c.name, m.name, pass, got, want)
				}
				h.Reset()
			}
		}
	}
}
