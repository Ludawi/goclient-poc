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
	// 1.1 Pull controllers public key
	controllerKey, err := GetControllerKey()
	if err != nil {
		fmt.Printf("Failed to pull Controllers public key %v\n", err)
		return
	}
	fmt.Printf("Client Key: %x\n", pubKey)
	fmt.Printf("Controller Key: %s\n", controllerKey)

	// 2. Connect or Enroll with controller
	Whoami(pubKey, privKey)

}

func Whoami(pubkey []byte, privkey []byte) {
	// a universal way to know the identity of a client
	// 		Send a signed message to /whoami route
	timestamp := time.Now().Unix()

	signedMessage := fmt.Sprintf("%d:%s", timestamp, base64.StdEncoding.EncodeToString(pubkey))
	signature := ed25519.Sign(privkey, []byte(signedMessage))

	fmt.Println(base64.StdEncoding.EncodeToString(pubkey))

	payload := WhoAmIRequest{
		PublicKey: base64.StdEncoding.EncodeToString(pubkey),
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshalling request %v\n", err)
		return
	}

	resp, err := http.Post("http://127.0.0.1:8080/api/whoami", "application/json", bytes.NewBuffer(jsonBody)) //  PLACEHOLDER global var
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

func GetControllerKey() (string, error) {
	resp, err := http.Get("http://127.0.0.1:8080/api/signature")
	if err != nil {
		fmt.Printf("Failed to connect to controller %v\n", err)
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		ControllerKey string `json:"public_key"`
	}

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error decoding JSON response %v\n", err)
			return "", err
		}
	} else {
		fmt.Printf("Controller returned unexpected response %v\n", resp.StatusCode)
		return "", err
	}

	return result.ControllerKey, err
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
		fmt.Println("Did not find a keyfile at the specified location, creating a new client...")
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
