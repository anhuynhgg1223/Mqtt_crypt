package elgamal

import (
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/openpgp/elgamal"
)

var p, _ = new(big.Int).SetString("FCA682CE8E12CABA26EFCCF7110E526DB078B05EDECBCD1EB4A208F3AE1617AE01F35B91A47E6DF63413C5E12ED0899BCD132ACD50D99151BDC43EE737592E17", 16)
var g, _ = new(big.Int).SetString("678471B27A9CF44EE91A49C5147DB1A9AAF244F05A434D6486931D2D14271B9E35030B71FD73DA179069B32E2935630E1C2062354D0DA20A6C416E50BE794CA4", 16)

type Cipher struct {
	A *big.Int
	B *big.Int
}

func KeyGen() (*elgamal.PrivateKey, *elgamal.PublicKey, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(256), nil).Sub(max, big.NewInt(1))

	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, err
	}

	y := new(big.Int).Exp(g, x, p)

	priv := &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			G: g,
			P: p,
			Y: y,
		},
		X: x,
	}
	return priv, &priv.PublicKey, nil
}

func Encrypt(message string, pub *elgamal.PublicKey) (*Cipher, error) {
	a, b, err := elgamal.Encrypt(rand.Reader, pub, []byte(message))
	if err != nil {
		return nil, err
	}
	return &Cipher{
		A: a,
		B: b,
	}, nil
}

func Decrypt(priv *elgamal.PrivateKey, ciphered *Cipher) ([]byte, error) {
	return elgamal.Decrypt(priv, ciphered.A, ciphered.B)
}
