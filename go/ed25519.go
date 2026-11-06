// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
)

// The checks SPEC.md § 8.4 (L-8.4-4) and § 5.4 make before the verification equation: the Go
// standard library checks S, and the equation, but not that the key and R decode canonically nor
// that they are not of small order, which let anyone forge a signature over about one message
// in eight.
var (
	curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveL = mustBig("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	curveD = func() *big.Int {
		num := new(big.Int).Sub(curveP, big.NewInt(121665))
		den := new(big.Int).ModInverse(big.NewInt(121666), curveP)
		return num.Mul(num, den).Mod(num, curveP)
	}()
	smallOrder = func() map[string]bool {
		set := map[string]bool{}
		for _, h := range []string{
			"0100000000000000000000000000000000000000000000000000000000000000",
			"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000080",
			"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
			"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
			"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
			"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		} {
			raw, _ := hex.DecodeString(h)
			set[string(raw)] = true
		}
		return set
	}()
)

func mustBig(h string) *big.Int {
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("lantern: bad constant")
	}
	return n
}

func littleEndian(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// decodesCanonically reports whether the 32 bytes are the canonical encoding of a point of the
// curve: a y below p, an x that exists, and no x = 0 with its sign bit set.
func decodesCanonically(enc []byte) bool {
	if len(enc) != 32 {
		return false
	}
	y := littleEndian(enc)
	sign := y.Bit(255)
	y.SetBit(y, 255, 0)
	if y.Cmp(curveP) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Mul(curveD, y2)
	v.Add(v, big.NewInt(1)).Mod(v, curveP)
	if v.Sign() == 0 {
		return false
	}
	x2 := u.Mul(u, new(big.Int).ModInverse(v, curveP))
	x2.Mod(x2, curveP)
	if x2.Sign() == 0 {
		return sign == 0
	}
	half := new(big.Int).Rsh(new(big.Int).Sub(curveP, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, half, curveP).Cmp(big.NewInt(1)) == 0
}

// StrictlyEncoded reports whether a public key and a signature pass the checks that come before
// the equation: both the key and R decode canonically, neither is one of the 8 points of small
// order, and S is reduced (below L).
func StrictlyEncoded(public, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	r := signature[:32]
	if !decodesCanonically(public) || !decodesCanonically(r) || smallOrder[string(public)] || smallOrder[string(r)] {
		return false
	}
	return littleEndian(signature[32:]).Cmp(curveL) < 0
}

// IsPublicKey reports whether raw is 32 bytes that decode canonically to a point not of small
// order (L-5.4-12).
func IsPublicKey(raw []byte) bool {
	return len(raw) == ed25519.PublicKeySize && decodesCanonically(raw) && !smallOrder[string(raw)]
}

// VerifyEd25519 verifies an Ed25519 signature as SPEC.md § 8.4 and § 5.4 require: the strict
// checks first, the equation after.
func VerifyEd25519(public, message, signature []byte) bool {
	return StrictlyEncoded(public, signature) && ed25519.Verify(public, message, signature)
}
