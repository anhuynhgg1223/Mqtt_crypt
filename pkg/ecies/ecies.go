package ecies

import (
	"encoding/base64"
	"os"

	"crypto/elliptic"

	proc "github.com/anhuynhgg1223/Mqtt_crypt/pkg/ProcessMeasure"
	ecies "github.com/ecies/go"
	"github.com/fomichev/secp256k1"
	"github.com/shirou/gopsutil/process"
)

func Ret_publicKey(publicKey_byte []byte) *ecies.PublicKey {
	curve := secp256k1.SECP256K1()
	x, y := elliptic.Unmarshal(curve, publicKey_byte)
	var publicKey ecies.PublicKey
	publicKey.Curve = curve
	publicKey.X = x
	publicKey.Y = y
	return &publicKey
}

func Ecies_Encrypt(secretMessage string, key *ecies.PublicKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go proc.GetProcStatus("ECC", "Encrypt", thisProc, stop)
	ciphertext, err := ecies.Encrypt(key, []byte(secretMessage))
	if err != nil {
		panic(err)
	}
	stop <- true
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func Ecies_Decrypt(cipherText string, privKey *ecies.PrivateKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go proc.GetProcStatus("ECC", "Decrypt", thisProc, stop)
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	plaintext, _ := ecies.Decrypt(privKey, ct)
	stop <- true
	return string(plaintext)
}
