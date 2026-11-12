package streebog

import (
	"hash"
	"testing"
)

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
