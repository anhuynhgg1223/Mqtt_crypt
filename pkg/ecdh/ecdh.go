package ecdh

import (
	"crypto"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	edch "github.com/aead/ecdh"
)

type KeyPair struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

var keyExchanger = edch.Generic(elliptic.P256())

func SingleSideKeyGeneration() (interface{}, error) {
	private, public, err := keyExchanger.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private/public key pair: %s\n", err)
		return nil, err
	}
	return KeyPair{
		privateKey: private,
		publicKey:  public,
	}, nil
}

func SecretKeyCompute(alice KeyPair, bob KeyPair) ([]byte, error) {
	err := keyExchanger.Check(alice.publicKey)
	if err != nil {
		fmt.Printf("Public key is not on the curve: %s\n", err)
		return nil, err
	}
	secret := keyExchanger.ComputeSecret(bob.privateKey, alice.publicKey)
	return secret, nil
}

func Encrypt(secret []byte, plain []byte) ([]byte, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		fmt.Printf("Cipher block create fail: %s\n", err)
		return nil, err
	}
	ciphered := make([]byte, len(plain))
	c.Encrypt(ciphered, plain)
	return ciphered, nil
}

func Decrypt(secret []byte, ciphertex []byte) ([]byte, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		fmt.Printf("Cipher block create fail: %s\n", err)
		return nil, err
	}
	plaintext := make([]byte, len(ciphertex))
	c.Decrypt(plaintext, ciphertex)
	return plaintext, nil
}
