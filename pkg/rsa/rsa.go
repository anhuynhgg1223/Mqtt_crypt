package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/allvisss/mqtt-v0/pkg/ProcessMeasure"
	"github.com/anhuynhgg1223/Capstone/mqtt_ecc/pkg/ProcessMeasure"
	"github.com/shirou/gopsutil/process"
)

type KeyPair struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

func KeyGeneration() (interface{}, error) {
	ProcessMeasure.GetProcStatus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate private/public key pair: %s\n", err)
		return nil, err
	}
	return KeyPair{
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey,
	}, nil
}

func RSA_Encrypt(secretMessage string, key rsa.PublicKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go proc.getProcStatus("Decrypt", thisProc, stop)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	stop <- true
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	fmt.Println("Plaintext:", string(plaintext))
	return string(plaintext)
}
