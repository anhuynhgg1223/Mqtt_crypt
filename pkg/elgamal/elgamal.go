package elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	Mrand "math/rand"

	"golang.org/x/crypto/openpgp/elgamal"
)

var one = big.NewInt(1)
var two = big.NewInt(2)

var ErrMessageLarge = errors.New("message bigger than public key")
var ErrCipherLarge = errors.New("cipher bigger than public key")

func GenerateKey(bitsize, probability int) (*elgamal.PrivateKey, error) {
	p, q, g, err := GeneratePQZp(bitsize, probability)
	if err != nil {
		panic("Element Gen ERROR")
	}

	randSource := Mrand.New(Mrand.NewSource(time.Now().UnixNano()))
	priv := new(big.Int).Rand(randSource, new(big.Int).Sub(q, one))
	y := new(big.Int).Exp(g, priv, p)

	var PubGalma elgamal.PublicKey
	var PriGalma elgamal.PrivateKey
	PubGalma.G = g
	PubGalma.P = p
	PubGalma.Y = y
	PriGalma.PublicKey = PubGalma
	PriGalma.X = priv
	return &PriGalma, nil
}

func GeneratePQZp(bitsize, probability int) (p, q, g *big.Int, err error) {
	return Gen(bitsize, probability)
}

func Gen(n, probability int) (*big.Int, *big.Int, *big.Int, error) {
	for {
		q, err := rand.Prime(rand.Reader, n-1)
		if err != nil {
			return nil, nil, nil, err
		}
		t := new(big.Int).Mul(q, two)
		p := new(big.Int).Add(t, one)
		if p.ProbablyPrime(probability) {
			for {
				g, err := rand.Int(rand.Reader, p)
				if err != nil {
					return nil, nil, nil, err
				}
				b := new(big.Int).Exp(g, two, p)
				if b.Cmp(one) == 0 {
					continue
				}
				b = new(big.Int).Exp(g, q, p)
				if b.Cmp(one) == 0 {
					return p, q, g, nil
				}
			}
		}
	}
}

func Encrypt(pub elgamal.PublicKey, message []byte) ([]byte, []byte, error) {
	k, err := rand.Int(rand.Reader, pub.P)
	if err != nil {
		return nil, nil, err
	}

	m := new(big.Int).SetBytes(message)
	if m.Cmp(pub.P) == 1 {
		return nil, nil, ErrMessageLarge
	}

	c1 := new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	c2 := new(big.Int).Mod(
		new(big.Int).Mul(m, s),
		pub.P,
	)
	return c1.Bytes(), c2.Bytes(), nil
}

func Decrypt(priv *elgamal.PrivateKey, cipher1, cipher2 []byte) ([]byte, error) {
	c1 := new(big.Int).SetBytes(cipher1)
	c2 := new(big.Int).SetBytes(cipher2)
	if c1.Cmp(priv.P) == 1 && c2.Cmp(priv.P) == 1 {
		return nil, ErrCipherLarge
	}

	s := new(big.Int).Exp(c1, priv.X, priv.P)
	if s.ModInverse(s, priv.P) == nil {
		return nil, errors.New("elgamal: invalid private key")
	}

	m := new(big.Int).Mod(
		new(big.Int).Mul(s, c2),
		priv.P,
	)
	return m.Bytes(), nil
}
