package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Request struct {
	ClientId  string  `json:"client_id"`
	Timestamp int64   `json:"timestamp"`
	Data      Payload `json:"data"`
	Signature string  `json:"signature"`
}

type Payload struct {
	Status  string         `json:"status"`
	Metrics map[string]any `json:"metrics"`
}

type WhoAmIRequest struct {
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type EnrollmentRequest struct {
	PublicKey   string `json:"public_key"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
	Hostname    string `json:"hostname"`
	AdminSecret string `json:"admin_secret"`
}

type Secrets struct {
	Pubkey  string `json:"pubkey"`
	Privkey string `json:"privkey"`
}

func main() {

	startup()
}

func startup() {
	// 1. Validate or Creata ed25519 key pair.
	pubKey, privKey, err := LoadKeyPairs("./secrets.json")
	if err != nil {
		fmt.Printf("Failed to initialize keys: %v\n", err)
		return
	}
	fmt.Printf("pubkey: %x\nprivkey: %x\n", pubKey, privKey)
	// 2. Connect or Enroll with controller
	// 		Send a signed message to /whoami route
	timestamp := time.Now().Unix()

	signedMessage := fmt.Sprintf("%d:%s", timestamp, base64.StdEncoding.EncodeToString(pubKey))
	signature := ed25519.Sign(privKey, []byte(signedMessage))

	payload := WhoAmIRequest{
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshalling request %v\n", err)
		return
	}

	resp, err := http.Post("http://localhost:8088/whoami", "application/json,", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("Failed to connect to controller %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("2xx response")
	} else {
		fmt.Printf("non-2xx response")
	}

}

func LoadKeyPairs(keyfile string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(keyfile); err == nil {
		// File exists, read and decode
		fileData, err := os.ReadFile(keyfile)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading keyfile: %w", err)
		}

		var keys Secrets
		if err := json.Unmarshal(fileData, &keys); err != nil {
			return nil, nil, fmt.Errorf("error unmarshaling JSON keyfile: %w", err)
		}

		pubKey, errPub := base64.StdEncoding.DecodeString(keys.Pubkey)
		privKey, errPriv := base64.StdEncoding.DecodeString(keys.Privkey)
		if errPub != nil || errPriv != nil {
			return nil, nil, errors.New("error decoding base64 encoded keys from file")
		}

		return ed25519.PublicKey(pubKey), ed25519.PrivateKey(privKey), nil

	} else if errors.Is(err, os.ErrNotExist) {
		// File does not exist, generate new key pair
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating ed25519 key: %w", err)
		}

		s := Secrets{
			Pubkey:  base64.StdEncoding.EncodeToString(pubKey),
			Privkey: base64.StdEncoding.EncodeToString(privKey),
		}

		jsonData, err := json.MarshalIndent(s, "", " ")
		if err != nil {
			return nil, nil, fmt.Errorf("error marshaling new keypair: %w", err)
		}

		if err := os.WriteFile(keyfile, jsonData, 0600); err != nil { // 0600 permissions for private keys!
			return nil, nil, fmt.Errorf("error saving keypair to file: %w", err)
		}

		return pubKey, privKey, nil
	} else {
		return nil, nil, fmt.Errorf("unexpected error checking keyfile: %w", err)
	}
}
