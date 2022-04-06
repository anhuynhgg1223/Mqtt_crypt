package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	oecc "github.com/anhuynhgg1223/Mqtt_crypt/pkg/ecies"
	oelg "github.com/anhuynhgg1223/Mqtt_crypt/pkg/elgamal"
	orsa "github.com/anhuynhgg1223/Mqtt_crypt/pkg/rsa"
	"golang.org/x/crypto/openpgp/elgamal"

	ecc "github.com/ecies/go"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type Config struct {
	ID          string
	Ip          string
	Port        int
	Username    string
	Passwd      string
	Topic       string
	OpponentID  string
	TypeEncrypt string
}

type flagKey struct {
	name   string
	isCome bool
}

type ElgMsg struct {
	msgFrag1 []byte
	msgFrag2 []byte
}

type elgSupport struct {
	elgCount  int
	selfCount int
	elgMessg  ElgMsg
	pubb      elgamal.PublicKey
}

var conf Config
var KeyMonitor flagKey
var client mqtt.Client
var opponentPublicKey interface{}
var ourKey interface{}
var sup elgSupport
var skipFlag bool

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	if KeyMonitor.isCome {
		switch KeyMonitor.name {
		case "rsa":
			opponentPublicKey, _ = x509.ParsePKCS1PublicKey(msg.Payload())
			fmt.Println("RSA key gotten!")
			KeyMonitor.isCome = false
		case "ecc":
			opponentPublicKey = oecc.Ret_publicKey(msg.Payload())
			fmt.Println("ECC key gotten!")
			KeyMonitor.isCome = false
		case "elg":
			switch sup.elgCount {
			case 3:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				sup.pubb.G = big.NewInt(1)
				fmt.Println("=================================== Get Key G =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*sup.pubb.G = *temp
				sup.elgCount--
			case 2:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				sup.pubb.P = big.NewInt(1)
				fmt.Println("=================================== Get Key P =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*sup.pubb.P = *temp
				sup.elgCount--
			case 1:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				sup.pubb.Y = big.NewInt(1)
				fmt.Println("=================================== Get Key y =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*sup.pubb.Y = *temp
				opponentPublicKey = sup.pubb
				fmt.Println("ELG key gotten!")
				sup.elgCount = 2
				KeyMonitor.isCome = false
				skipFlag = true
			}
		}
	}
	switch string(msg.Payload()) {
	case "reqKeyRSA" + conf.OpponentID:
		pub([]byte("Keycoming" + conf.ID))
		pub(x509.MarshalPKCS1PublicKey(&ourKey.(*rsa.PrivateKey).PublicKey))
	case "reqKeyECC" + conf.OpponentID:
		publicKeyByte := elliptic.Marshal(ourKey.(*ecc.PrivateKey).PublicKey.Curve, ourKey.(*ecc.PrivateKey).PublicKey.X, ourKey.(*ecc.PrivateKey).PublicKey.Y)
		pub([]byte("Keycoming" + conf.ID))
		pub(publicKeyByte)
	case "reqKeyELG" + conf.OpponentID:
		pub([]byte("ELGKeycoming" + conf.ID))
		sup.selfCount = 3
		by, _ := ourKey.(*elgamal.PrivateKey).PublicKey.G.MarshalJSON()
		pub(by)
		time.Sleep(time.Millisecond * 100)
		by, _ = ourKey.(*elgamal.PrivateKey).PublicKey.P.MarshalJSON()
		pub(by)
		time.Sleep(time.Millisecond * 100)
		by, _ = ourKey.(*elgamal.PrivateKey).PublicKey.Y.MarshalJSON()
		pub(by)
	case "Keycoming" + conf.OpponentID:
		KeyMonitor.isCome = true
	case "ELGKeycoming" + conf.OpponentID:
		KeyMonitor.isCome = true
		sup.elgCount = 3
	default:
		if string(msg.Payload()) == "reqKeyRSA"+conf.ID || string(msg.Payload()) == "reqKeyECC"+conf.ID || string(msg.Payload()) == "Keycoming"+conf.ID || string(msg.Payload()) == "reqKeyELG"+conf.ID || string(msg.Payload()) == "ELGKeycoming"+conf.ID || skipFlag {
			skipFlag = false
		} else {
			switch KeyMonitor.name {
			case "rsa":
				plain := orsa.RSA_Decrypt(string(msg.Payload()), ourKey.(*rsa.PrivateKey))
				fmt.Printf("Received message: %v \n========\n", plain)
			case "ecc":
				plain := oecc.Ecies_Decrypt(string(msg.Payload()), ourKey.(*ecc.PrivateKey))
				fmt.Printf("Received message: %v \n========\n", plain)
			case "elg":

				if !KeyMonitor.isCome && sup.selfCount == 0 {
					if sup.elgCount == 1 {
						sup.elgMessg.msgFrag2 = msg.Payload()
						plain, err := oelg.Decrypt(ourKey.(*elgamal.PrivateKey), sup.elgMessg.msgFrag1, sup.elgMessg.msgFrag2)
						if err != nil {
							panic(err)
						}
						sup.elgCount++
						fmt.Printf("Received message: %s \n========\n", plain)
					} else {
						sup.elgMessg.msgFrag1 = msg.Payload()
						sup.elgCount--
					}
				}

				if sup.selfCount > 0 {
					sup.selfCount--
				}
			}
		}
	}
}

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	fmt.Println("Connected")
}

var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
	fmt.Printf("Connect lost: %v", err)
}

func main() {
	readConf()
	generate_Key()
	setClient()
	sub()
	core()

}

func core() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		var text string
		scanner.Scan()
		text = scanner.Text()
		switch KeyMonitor.name {
		case "rsa":
			cipher := orsa.RSA_Encrypt(text, opponentPublicKey.(*rsa.PublicKey))
			skipFlag = true
			pub([]byte(cipher))
		case "ecc":
			cipher := oecc.Ecies_Encrypt(text, opponentPublicKey.(*ecc.PublicKey))
			skipFlag = true
			pub([]byte(cipher))
		case "elg":
			cipher1, cipher2, _ := oelg.Encrypt(opponentPublicKey.(elgamal.PublicKey), []byte(text))
			pub(cipher1)
			pub(cipher2)
		}
	}
}
func pub(message []byte) {
	token := client.Publish(conf.Topic, 0, false, message)
	token.Wait()
}

func sub() {
	token := client.Subscribe(conf.Topic, 1, nil)
	token.Wait()
	fmt.Printf("Subscribed to topic: %s \n", conf.Topic)
	reqKey()
}

func reqKey() {
	fmt.Println("Waiting for opponent key...")
	for opponentPublicKey == nil {
		switch KeyMonitor.name {
		case "rsa":
			pub([]byte("reqKeyRSA" + conf.ID))
		case "ecc":
			pub([]byte("reqKeyECC" + conf.ID))
		case "elg":
			pub([]byte("reqKeyELG" + conf.ID))
		}
		time.Sleep(time.Millisecond * 2000)
	}
}

func generate_Key() {
	switch KeyMonitor.name {
	case "rsa":
		ourKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	case "ecc":
		ourKey, _ = ecc.GenerateKey()
	case "elg":
		ourKey, _ = oelg.GenerateKey(512, 1)
	}
}

func readConf() {
	contenIn, _ := ioutil.ReadFile("config.json")
	json.Unmarshal(contenIn, &conf)
	KeyMonitor.name = conf.TypeEncrypt
	KeyMonitor.isCome = false
}

func setClient() {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", conf.Ip, conf.Port))
	opts.SetClientID("go_mqtt_client_" + conf.ID)
	opts.SetUsername(conf.Username)
	opts.SetPassword(conf.Passwd)
	opts.SetDefaultPublishHandler(messagePubHandler)
	opts.OnConnect = connectHandler
	opts.OnConnectionLost = connectLostHandler
	client = mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
}
