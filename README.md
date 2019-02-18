```
package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws/credentials"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	"github.com/hixi-hyi/awsiotdevice"
)

var defaultMTTTHandler MQTT.MessageHandler = func(client MQTT.Client, message MQTT.Message) {
	fmt.Printf("Received MQTT message on topic: %s\n", message.Topic())
}

func main() {
	creds := credentials.NewStaticCredentials(
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
	)
	config := awsiotdevice.NewConfig().WithEndpoint("xxxxx.iot.ap-northeast-1.amazonaws.com").WithRegion("ap-northeast-1").WithCredentials(creds)
	url, err := awsiotdevice.GetIoTSigV4Url(config)
	if err != nil {
		fmt.Println(err)
		return
	}

    // 以下検証ロジック

	fin := make(chan bool)
	opts := MQTT.NewClientOptions().AddBroker(url).SetClientID("test")
	opts.SetDefaultPublishHandler(defaultMTTTHandler)

	client := MQTT.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	topic := fmt.Sprintf("#")

	if token := client.Subscribe(topic, 0, nil); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
	fmt.Printf("Subscribe topic: %s\n", topic)

	<-fin
}
```
