package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"io"
	"math/big"
)

type Signature struct {
	r *big.Int
	s *big.Int
}

func KeyGen() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	return priv, pub, nil
}

func Sign(message string, privateKey *ecdsa.PrivateKey) (*Signature, error) {
	h := md5.New()
	io.WriteString(h, message)
	signhash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, signhash)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.r = r
	sig.s = s
	return sig, nil
}

func Verify(message string, publicKey *ecdsa.PublicKey, sig *Signature) bool {
	h := md5.New()
	io.WriteString(h, message)
	signhash := h.Sum(nil)

	verified := ecdsa.Verify(publicKey, signhash, sig.r, sig.s)
	return verified
}
