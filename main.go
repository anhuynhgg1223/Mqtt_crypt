package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
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
			switch elgCount {
			case 3:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				pubb.G = big.NewInt(1)
				fmt.Println("=================================== Get Key G =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*pubb.G = *temp
				elgCount--
			case 2:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				pubb.P = big.NewInt(1)
				fmt.Println("=================================== Get Key P =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*pubb.P = *temp
				elgCount--
			case 1:
				temp := big.NewInt(1)
				temp.UnmarshalJSON(msg.Payload())
				pubb.Y = big.NewInt(1)
				fmt.Println("=================================== Get Key y =======================================")
				fmt.Println(temp)
				fmt.Println("=====================================================================================")
				*pubb.Y = *temp
				opponentPublicKey = pubb
				fmt.Println("ELG key gotten!")
				elgCount = 2
				KeyMonitor.isCome = false
				skipFlag = true
			}
		}
	}
	switch string(msg.Payload()) {
	case "reqKeyRSA" + thatClient:
		pub([]byte("Keycoming" + thisClient))
		pub(x509.MarshalPKCS1PublicKey(&ourKey.(*rsa.PrivateKey).PublicKey))
	case "reqKeyECC" + thatClient:
		publicKeyByte := elliptic.Marshal(ourKey.(*ecc.PrivateKey).PublicKey.Curve, ourKey.(*ecc.PrivateKey).PublicKey.X, ourKey.(*ecc.PrivateKey).PublicKey.Y)
		pub([]byte("Keycoming" + thisClient))
		pub(publicKeyByte)
	case "reqKeyELG" + thatClient:
		pub([]byte("ELGKeycoming" + thisClient))
		selfCount = 3
		by, _ := ourKey.(*elgamal.PrivateKey).PublicKey.G.MarshalJSON()
		pub(by)
		time.Sleep(time.Millisecond * 100)
		by, _ = ourKey.(*elgamal.PrivateKey).PublicKey.P.MarshalJSON()
		pub(by)
		time.Sleep(time.Millisecond * 100)
		by, _ = ourKey.(*elgamal.PrivateKey).PublicKey.Y.MarshalJSON()
		pub(by)
	case "Keycoming" + thatClient:
		KeyMonitor.isCome = true
	case "ELGKeycoming" + thatClient:
		KeyMonitor.isCome = true
		elgCount = 3
	default:
		if string(msg.Payload()) == "reqKeyRSA"+thisClient || string(msg.Payload()) == "reqKeyECC"+thisClient || string(msg.Payload()) == "Keycoming"+thisClient || string(msg.Payload()) == "reqKeyELG"+thisClient || string(msg.Payload()) == "ELGKeycoming"+thisClient || skipFlag {
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

				if !KeyMonitor.isCome && selfCount == 0 {
					if elgCount == 1 {
						elgMessg.msgFrag2 = msg.Payload()
						plain, err := oelg.Decrypt(ourKey.(*elgamal.PrivateKey), elgMessg.msgFrag1, elgMessg.msgFrag2)
						if err != nil {
							panic(err)
						}
						elgCount++
						fmt.Printf("Received message: %s \n========\n", plain)
					} else {
						elgMessg.msgFrag1 = msg.Payload()
						elgCount--
					}
				}

				if selfCount > 0 {
					selfCount--
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

type flagKey struct {
	name   string
	isCome bool
}

type ElgMsg struct {
	msgFrag1 []byte
	msgFrag2 []byte
}

var KeyMonitor flagKey
var client mqtt.Client
var opponentPublicKey interface{}
var ourKey interface{}
var elgCount int
var selfCount int
var elgMessg ElgMsg
var pubb elgamal.PublicKey
var skipFlag bool

var topic = "topic/test"
var thisClient = "1"
var thatClient = "2"

func main() {
	KeyMonitor.name = "rsa"
	KeyMonitor.isCome = false
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
			pub([]byte(cipher))
		case "ecc":
			cipher := oecc.Ecies_Encrypt(text, opponentPublicKey.(*ecc.PublicKey))
			pub([]byte(cipher))
		case "elg":
			cipher1, cipher2, _ := oelg.Encrypt(opponentPublicKey.(elgamal.PublicKey), []byte(text))
			pub(cipher1)
			pub(cipher2)
		}
	}
}
func pub(message []byte) {
	token := client.Publish(topic, 0, false, message)
	token.Wait()
}

func sub() {
	token := client.Subscribe(topic, 1, nil)
	token.Wait()
	fmt.Printf("Subscribed to topic: %s \n", topic)
	reqKey()
}

func reqKey() {
	fmt.Println("Waiting for opponent key...")
	for opponentPublicKey == nil {
		switch KeyMonitor.name {
		case "rsa":
			pub([]byte("reqKeyRSA" + thisClient))
		case "ecc":
			pub([]byte("reqKeyECC" + thisClient))
		case "elg":
			pub([]byte("reqKeyELG" + thisClient))
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

func setClient() {
	var broker = "192.168.208.143"
	var port = 1883
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", broker, port))
	opts.SetClientID("go_mqtt_client" + thisClient)
	opts.SetUsername("rasOS")
	opts.SetPassword("12345")
	opts.SetDefaultPublishHandler(messagePubHandler)
	opts.OnConnect = connectHandler
	opts.OnConnectionLost = connectLostHandler
	client = mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
}
