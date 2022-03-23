package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	oecc "github.com/anhuynhgg1223/Mqtt_crypt/pkg/ecies"
	orsa "github.com/anhuynhgg1223/Mqtt_crypt/pkg/rsa"
	ecc "github.com/ecies/go"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	if KeyMonitor.isCome {
		switch KeyMonitor.name {
		case "rsa":
			opponentPublicKey, _ = x509.ParsePKCS1PublicKey(msg.Payload())
			fmt.Println("RSA key gotten!")
		case "ecc":
			opponentPublicKey = oecc.Ret_publicKey(msg.Payload())
			fmt.Println("ECC key gotten!")
		}
		KeyMonitor.isCome = false
	}
	switch string(msg.Payload()) {
	case "reqKeyRSA" + thatClient:
		pub([]byte("Keycoming" + thisClient))
		pub(x509.MarshalPKCS1PublicKey(&ourKey.(*rsa.PrivateKey).PublicKey))
	case "reqKeyECC" + thatClient:
		publicKeyByte := elliptic.Marshal(ourKey.(*ecc.PrivateKey).PublicKey.Curve, ourKey.(*ecc.PrivateKey).PublicKey.X, ourKey.(*ecc.PrivateKey).PublicKey.Y)
		pub([]byte("Keycoming" + thisClient))
		pub(publicKeyByte)
	case "Keycoming" + thatClient:
		KeyMonitor.isCome = true
	default:
		if string(msg.Payload()) == "reqKeyRSA"+thisClient || string(msg.Payload()) == "reqKeyECC"+thisClient || string(msg.Payload()) == "Keycoming" {
			fmt.Println("Waiting for opponent key...")
		} else {
			switch KeyMonitor.name {
			case "rsa":
				plain := orsa.RSA_Decrypt(string(msg.Payload()), ourKey.(*rsa.PrivateKey))
				fmt.Printf("Received message: %v \n========\n", plain)
			case "ecc":
				plain := oecc.Ecies_Decrypt(string(msg.Payload()), ourKey.(*ecc.PrivateKey))
				fmt.Printf("Received message: %v \n========\n", plain)
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

var KeyMonitor flagKey
var client mqtt.Client
var opponentPublicKey interface{}
var ourKey interface{}

var topic = "topic/test"
var thisClient = "2"
var thatClient = "1"

func main() {
	KeyMonitor.name = "ecc"
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
	for opponentPublicKey == nil {
		switch KeyMonitor.name {
		case "rsa":
			pub([]byte("reqKeyRSA" + thisClient))
		case "ecc":
			pub([]byte("reqKeyECC" + thisClient))
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
