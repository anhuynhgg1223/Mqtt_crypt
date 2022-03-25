package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"

	proc "github.com/anhuynhgg1223/Mqtt_crypt/pkg/ProcessMeasure"
	"github.com/shirou/gopsutil/process"
)

func RSA_Encrypt(secretMessage string, key *rsa.PublicKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go proc.GetProcStatus("RSA", "Encrypt", thisProc, stop)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rng, key, []byte(secretMessage), label)
	stop <- true
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_Decrypt(cipherText string, privKey *rsa.PrivateKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go proc.GetProcStatus("RSA", "Decrypt", thisProc, stop)
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rng, privKey, ct, label)
	stop <- true
	return string(plaintext)
}
