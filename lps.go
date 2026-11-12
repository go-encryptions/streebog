package streebog

// lps8 is lps unrolled over eight locals: output word w is the XOR over k of
// tab[k][byte w of input word k].
func lps8(t *[8][256]uint64, a0, a1, a2, a3, a4, a5, a6, a7 uint64) (uint64, uint64, uint64, uint64, uint64, uint64, uint64, uint64) {
	r0 := t[0][byte(a0)] ^ t[1][byte(a1)] ^ t[2][byte(a2)] ^ t[3][byte(a3)] ^ t[4][byte(a4)] ^ t[5][byte(a5)] ^ t[6][byte(a6)] ^ t[7][byte(a7)]
	r1 := t[0][byte(a0>>8)] ^ t[1][byte(a1>>8)] ^ t[2][byte(a2>>8)] ^ t[3][byte(a3>>8)] ^ t[4][byte(a4>>8)] ^ t[5][byte(a5>>8)] ^ t[6][byte(a6>>8)] ^ t[7][byte(a7>>8)]
	r2 := t[0][byte(a0>>16)] ^ t[1][byte(a1>>16)] ^ t[2][byte(a2>>16)] ^ t[3][byte(a3>>16)] ^ t[4][byte(a4>>16)] ^ t[5][byte(a5>>16)] ^ t[6][byte(a6>>16)] ^ t[7][byte(a7>>16)]
	r3 := t[0][byte(a0>>24)] ^ t[1][byte(a1>>24)] ^ t[2][byte(a2>>24)] ^ t[3][byte(a3>>24)] ^ t[4][byte(a4>>24)] ^ t[5][byte(a5>>24)] ^ t[6][byte(a6>>24)] ^ t[7][byte(a7>>24)]
	r4 := t[0][byte(a0>>32)] ^ t[1][byte(a1>>32)] ^ t[2][byte(a2>>32)] ^ t[3][byte(a3>>32)] ^ t[4][byte(a4>>32)] ^ t[5][byte(a5>>32)] ^ t[6][byte(a6>>32)] ^ t[7][byte(a7>>32)]
	r5 := t[0][byte(a0>>40)] ^ t[1][byte(a1>>40)] ^ t[2][byte(a2>>40)] ^ t[3][byte(a3>>40)] ^ t[4][byte(a4>>40)] ^ t[5][byte(a5>>40)] ^ t[6][byte(a6>>40)] ^ t[7][byte(a7>>40)]
	r6 := t[0][byte(a0>>48)] ^ t[1][byte(a1>>48)] ^ t[2][byte(a2>>48)] ^ t[3][byte(a3>>48)] ^ t[4][byte(a4>>48)] ^ t[5][byte(a5>>48)] ^ t[6][byte(a6>>48)] ^ t[7][byte(a7>>48)]
	r7 := t[0][byte(a0>>56)] ^ t[1][byte(a1>>56)] ^ t[2][byte(a2>>56)] ^ t[3][byte(a3>>56)] ^ t[4][byte(a4>>56)] ^ t[5][byte(a5>>56)] ^ t[6][byte(a6>>56)] ^ t[7][byte(a7>>56)]
	return r0, r1, r2, r3, r4, r5, r6, r7
}
