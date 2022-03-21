package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	orsa "Mqtt_crypt/pkg/rsa"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/shirou/gopsutil/process"
)

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	if string(msg.Payload()) == "setkey!@#$%^&*" {
		flagKey = true
	} else {
		if flagKey {
			OpPublicKeyx, _ := x509.ParsePKCS1PublicKey(msg.Payload())
			OpPublicKey = *OpPublicKeyx
			fmt.Printf("Key taken!\n=======\n")
			fmt.Print("Input message: ")
			flagKey = false
		} else {

			plain := RSA_Decrypt(string(msg.Payload()), Keyy)
			fmt.Printf("Received message: %v \n========\n", plain)
			fmt.Print("Input message: ")
		}
	}
}

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	fmt.Println("Connected")
}

var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
	fmt.Printf("Connect lost: %v", err)
}

var flagKey = false
var OpPublicKey rsa.PublicKey
var Keyy rsa.PrivateKey

var topic = "topic/test"

func main() {
	Key, _ := rsa.GenerateKey(rand.Reader, 2048)
	Keyy = *Key
	okk := x509.MarshalPKCS1PublicKey(&Key.PublicKey)
	// kkk, _ := x509.ParsePKCS1PublicKey(kk)

	client := *setClient()
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
	sub(client)

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Input message: ")
	for {
		var text string
		scanner.Scan()
		text = scanner.Text()
		if text == "!@#" {
			token := client.Publish(topic, 0, false, "setkey!@#$%^&*")
			token.Wait()
			token = client.Publish(topic, 0, false, okk)
			token.Wait()
		} else {
			if (OpPublicKey == rsa.PublicKey{}) {
				fmt.Println("Don't have public key yet!")
			} else {
				cipher := orsa.RSA_Encrypt(text, OpPublicKey)
				token := client.Publish(topic, 0, false, cipher)
				token.Wait()
			}
		}

	}
}

func sub(client mqtt.Client) {
	token := client.Subscribe(topic, 1, nil)
	token.Wait()
	fmt.Printf("Subscribed to topic: %s \n", topic)
}

func setClient() *mqtt.Client {
	var broker = "192.168.208.143"
	var port = 1883
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", broker, port))
	opts.SetClientID("go_mqtt_client2")
	opts.SetUsername("rasOS")
	opts.SetPassword("12345")
	opts.SetDefaultPublishHandler(messagePubHandler)
	opts.OnConnect = connectHandler
	opts.OnConnectionLost = connectLostHandler
	client := mqtt.NewClient(opts)
	return &client
}

// ===============================================================================================

func RSA_Encrypt(secretMessage string, key rsa.PublicKey) string {
	thisProc, _ := process.NewProcess(int32(os.Getpid()))
	stop := make(chan bool)
	go getProcStatus("Encrypt", thisProc, stop)

	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	stop <- true
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	// thisProc, _ := process.NewProcess(int32(os.Getpid()))
	// stop := make(chan bool)
	// go getProcStatus("Decrypt", thisProc, stop)
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	// stop <- true
	return string(plaintext)
}

func getProcStatus(place string, p *process.Process, stop chan bool) {
	fo, err := os.OpenFile(place+"_Output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("panik!")
	}
	fo.WriteString(place + " Metric Data (%): \n")
	defer fo.Close()
	for {
		select {
		case <-stop:
			close(stop)
			return
		default:
			{
				c, _ := p.CPUPercent()
				m, _ := p.MemoryPercent()
				fo.WriteString(fmt.Sprintf("CPU: %v  Memory: %v \n", c, m))
			}
		}
	}
}
