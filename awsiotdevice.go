package awsiotdevice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	timeFormat      = "20060102T150405Z"
	shortTimeFormat = "20060102"
)

type Config struct {
	Credentials *credentials.Credentials
	Endpoint    string
	Region      string
	TimeFn      func() time.Time
}

func NewConfig() *Config {
	return &Config{}
}
func (c *Config) WithCredentials(creds *credentials.Credentials) *Config {
	c.Credentials = creds
	return c
}

func (c *Config) WithEndpoint(endpoint string) *Config {
	c.Endpoint = endpoint
	return c
}
func (c *Config) WithRegion(region string) *Config {
	c.Region = region
	return c
}

func GetIoTSigV4Url(c *Config) (string, error) {
	// creds
	creds, err := c.Credentials.Get()
	if err != nil {
		return "", err
	}
	accessKeyId := creds.AccessKeyID
	secretAccessKey := creds.SecretAccessKey
	sessionToken := creds.SessionToken

	// date
	if c.TimeFn == nil {
		c.TimeFn = time.Now().UTC
	}
	current := c.TimeFn()
	today := current.Format(shortTimeFormat)
	now := current.Format(timeFormat)

	// others
	hostname := c.Endpoint
	region := c.Region

	// iot
	method := "GET"
	scheme := "wss://"
	path := "/mqtt"
	serviceName := "iotdevicegateway"
	signedHeaders := "host"

	// 1. Create a canonical request for Signature Version 4.
	canonicalHeaders := "host:" + strings.ToLower(hostname) + "\n"
	canonicalQueryString := "X-Amz-Algorithm=AWS4-HMAC-SHA256"
	canonicalQueryString += "&X-Amz-Credential=" + accessKeyId + "%2F" + today + "%2F" + "ap-northeast-1" + "%2F" + "iotdevicegateway" + "%2Faws4_request"
	canonicalQueryString += "&X-Amz-Date=" + now
	canonicalQueryString += "&X-Amz-SignedHeaders=host"
	canonicalRequest := method + "\n" + path + "\n" + canonicalQueryString + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// 2. Create a string to sign, generate a signing key, and sign the string.
	hashedCanonicalRequest := makeSha256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + now + "\n" + today + "/" + region + "/" + serviceName + "/aws4_request\n" + hashedCanonicalRequest
	signingKey := getSignatureKey(secretAccessKey, today, region, serviceName)
	signature := hex.EncodeToString(makeHmac(signingKey, []byte(stringToSign)))

	// 3. Add the signing information to the request.
	finalParams := canonicalQueryString + "&X-Amz-Signature=" + signature

	// 4. If you have session credentials (from an STS server, AssumeRole, or Amazon Cognito), append the session token to the end of the URL string after signing:
	if sessionToken != "" {
		finalParams += "&X-Amz-Security-Token=" + url.QueryEscape(sessionToken)
	}

	// 5. Prepend the protocol, host, and URI to the canonicalQuerystring:
	url := scheme + hostname + path + "?" + finalParams
	return url, nil
}

func getSignatureKey(secret, today, region, serviceName string) []byte {
	kdate := makeHmac([]byte("AWS4"+secret), []byte(today))
	kregion := makeHmac(kdate, []byte(region))
	kservice := makeHmac(kregion, []byte(serviceName))
	kcredentials := makeHmac(kservice, []byte("aws4_request"))
	return kcredentials
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
