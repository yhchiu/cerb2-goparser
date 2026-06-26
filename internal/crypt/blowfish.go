package crypt

// f is the Blowfish round function over the four bytes of x, matching F() in
// rsa.c. All additions are modulo 2^32 (uint32 wraparound).
func f(x uint32) uint32 {
	a := (x >> 24) & 0xff
	b := (x >> 16) & 0xff
	c := (x >> 8) & 0xff
	d := x & 0xff
	y := sBox[0][a] + sBox[1][b]
	y = y ^ sBox[2][c]
	y = y + sBox[3][d]
	return y
}

// decypher decrypts one 64-bit block (xl, xr). Mirrors rsa_decypher.
func decypher(xl, xr uint32) (uint32, uint32) {
	Xl, Xr := xl, xr
	for i := 17; i > 1; i-- { // N+1 .. 2
		Xl ^= pBox[i]
		Xr = f(Xl) ^ Xr
		Xl, Xr = Xr, Xl
	}
	Xl, Xr = Xr, Xl
	Xr ^= pBox[1]
	Xl ^= pBox[0]
	return Xl, Xr
}

// encypher encrypts one 64-bit block (xl, xr). Mirrors rsa_encypher; used to
// build test vectors (the inverse of decypher).
func encypher(xl, xr uint32) (uint32, uint32) {
	Xl, Xr := xl, xr
	for i := 0; i < 16; i++ { // 0 .. N-1
		Xl ^= pBox[i]
		Xr = f(Xl) ^ Xr
		Xl, Xr = Xr, Xl
	}
	Xl, Xr = Xr, Xl
	Xr ^= pBox[16] // P[N]
	Xl ^= pBox[17] // P[N+1]
	return Xl, Xr
}
