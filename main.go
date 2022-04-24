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
	"log"
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
	MsgFrag1 []byte
	MsgFrag2 []byte
}

type ElgSupply struct {
	MessData ElgMsg
	OPpubkey elgamal.PublicKey
	OUprikey *elgamal.PrivateKey
}

type LockFlag struct {
	Us   bool
	Them bool
}

var conf Config
var KeyMonitor flagKey
var client mqtt.Client
var opponentPublicKey interface{}
var ourKey interface{}
var elgSup ElgSupply
var skipFlag bool
var theLock LockFlag

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	if KeyMonitor.isCome {
		switch KeyMonitor.name {
		case "rsa":
			opponentPublicKey, _ = x509.ParsePKCS1PublicKey(msg.Payload())
			fmt.Println("RSA key gotten!")
		case "ecc":
			opponentPublicKey = oecc.Ret_publicKey(msg.Payload())
			fmt.Println("ECC key gotten!")
		case "elg":
			json.Unmarshal(msg.Payload(), &elgSup.OPpubkey)
			fmt.Println("ELG key gotten!")
			opponentPublicKey = true
		}
		KeyMonitor.isCome = false
		theLock.Us = true
		pub([]byte(conf.ID + "_isReady!"))
	} else {
		switch string(msg.Payload()) {
		case "reqKey" + conf.OpponentID:
			switch KeyMonitor.name {
			case "rsa":
				pub([]byte("Keycoming" + conf.ID))
				pub(x509.MarshalPKCS1PublicKey(&ourKey.(*rsa.PrivateKey).PublicKey))
			case "ecc":
				publicKeyByte := elliptic.Marshal(ourKey.(*ecc.PrivateKey).PublicKey.Curve, ourKey.(*ecc.PrivateKey).PublicKey.X, ourKey.(*ecc.PrivateKey).PublicKey.Y)
				pub([]byte("Keycoming" + conf.ID))
				pub(publicKeyByte)
			case "elg":
				pub([]byte("Keycoming" + conf.ID))
				PubOut, _ := json.Marshal(elgSup.OUprikey.PublicKey)
				pub(PubOut)
			}
		case "Keycoming" + conf.OpponentID:
			KeyMonitor.isCome = true
		case conf.OpponentID + "_isReady!":
			theLock.Them = true
		default:
			if !theLock.Us || !theLock.Them || skipFlag {
				skipFlag = false
			} else {
				switch KeyMonitor.name {
				case "rsa":
					plain := orsa.RSA_Decrypt(string(msg.Payload()), ourKey.(*rsa.PrivateKey))
					fmt.Printf("Received message: %v \n\n", plain)
				case "ecc":
					plain := oecc.Ecies_Decrypt(string(msg.Payload()), ourKey.(*ecc.PrivateKey))
					fmt.Printf("Received message: %v \n\n", plain)
				case "elg":
					json.Unmarshal(msg.Payload(), &elgSup.MessData)
					plain, _ := oelg.Decrypt(elgSup.OUprikey, elgSup.MessData.MsgFrag1, elgSup.MessData.MsgFrag2)
					fmt.Printf("Received message: %s \n\n", plain)
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
	scantype := bufio.NewScanner(os.Stdin)
	var textType string

	for {
		for textType != "start" {
			scantype.Scan()
			textType = scantype.Text()
		}
		file, err := os.Open("wordlist.txt")
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			time.Sleep(time.Millisecond * 50)
			text := scanner.Text()
			switch KeyMonitor.name {
			case "rsa":
				cipher := orsa.RSA_Encrypt(text, opponentPublicKey.(*rsa.PublicKey))
				pub([]byte(cipher))
			case "ecc":
				cipher := oecc.Ecies_Encrypt(text, opponentPublicKey.(*ecc.PublicKey))
				pub([]byte(cipher))
			case "elg":
				cipher1, cipher2, _ := oelg.Encrypt(elgSup.OPpubkey, []byte(text))
				elgSup.MessData.MsgFrag1 = cipher1
				elgSup.MessData.MsgFrag2 = cipher2
				contentOut, _ := json.Marshal(elgSup.MessData)
				pub(contentOut)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		file.Close()
		textType = "end"
	}
}

func pub(message []byte) {
	skipFlag = true
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
			pub([]byte("reqKey" + conf.ID))
		case "ecc":
			pub([]byte("reqKey" + conf.ID))
		case "elg":
			pub([]byte("reqKey" + conf.ID))
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
		elgSup.OUprikey, _ = oelg.GenerateKey(2048, 1)
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
