package streebog

import (
	"crypto/pbkdf2"
	"hash"
	"testing"
)

// BenchmarkPBKDF2HMAC is the VeraCrypt shape: PBKDF2-HMAC-Streebog-512, 64-byte
// output, 1000 iterations. crypto/hmac saves the keyed inner and outer states
// only if the hash marshals its state, which halves the compressions per
// iteration.
func BenchmarkPBKDF2HMAC(b *testing.B) {
	salt := make([]byte, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := pbkdf2.Key(New512, "password", salt, 1000, 64); err != nil {
			b.Fatal(err)
		}
	}
}

func benchSum(b *testing.B, size int, h hash.Hash) {
	buf := make([]byte, size)
	out := make([]byte, 0, Size512)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		out = h.Sum(out[:0])
	}
}

func BenchmarkSum512_1K(b *testing.B)  { benchSum(b, 1024, New512()) }
func BenchmarkSum512_64K(b *testing.B) { benchSum(b, 65536, New512()) }
func BenchmarkSum256_1K(b *testing.B)  { benchSum(b, 1024, New256()) }
func BenchmarkSum256_64K(b *testing.B) { benchSum(b, 65536, New256()) }
