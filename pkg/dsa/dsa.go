package dsa

import (
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"io"
	"math/big"
)

type Signature struct {
	r *big.Int
	s *big.Int
}

func KeyGen() (*dsa.PrivateKey, *dsa.PublicKey, error) {
	params := new(dsa.Parameters)
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L2048N256)
	if err != nil {
		return nil, nil, err
	}
	priv := new(dsa.PrivateKey)
	priv.PublicKey.Parameters = *params
	dsa.GenerateKey(priv, rand.Reader)
	pub := &priv.PublicKey

	return priv, pub, nil
}

func Sign(message string, privateKey *dsa.PrivateKey) (*Signature, error) {
	h := md5.New()
	io.WriteString(h, message)
	signhash := h.Sum(nil)

	r, s, err := dsa.Sign(rand.Reader, privateKey, signhash)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.r = r
	sig.s = s
	return sig, nil
}

func Verify(message string, publicKey *dsa.PublicKey, sig *Signature) bool {
	h := md5.New()
	io.WriteString(h, message)
	signhash := h.Sum(nil)

	verified := dsa.Verify(publicKey, signhash, sig.r, sig.s)
	return verified
}
