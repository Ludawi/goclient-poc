package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	// "golang.org/x/crypto/nacl/sign"
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
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type EnrollMessage struct {
	Hostname    string `json:"hostname"`
	AdminSecret string `json:"admin_secret"`
	Timestamp   int64  `json:"timestamp"`
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
	// 1.1. Pull controllers public key
	controllerKey, err := GetControllerKey()
	if err != nil {
		fmt.Printf("Failed to pull Controllers public key %v\n", err)
		return
	}
	fmt.Printf("Client Key: %x\n", pubKey)
	fmt.Printf("Controller Key: %s\n", controllerKey)

	// 2. Connect or Enroll with controller
	info, err := Whoami(pubKey, privKey)
	if err != nil {
		fmt.Println("Error requesting running whoami", err)
		return
	}
	fmt.Printf("Client Status: %v\n", info.Status)

}

type AgentStatus string

const (
	StatusUnknown     AgentStatus = "unknown"
	statusActive      AgentStatus = "active"
	statusInactive    AgentStatus = "inactive"
	statusWaiting     AgentStatus = "waiting"
	statusDeactivated AgentStatus = "deactivated"
)

type WhoAmIResponse struct {
	Hostname string   `json:"hostname,omitempty"`
	Status   string   `json:"status"`
	PubKey   string   `json:"pubkey,omitempty"`
	Profiles []string `json:"profiles,omitempty"`
}

func Whoami(pubkey []byte, privkey []byte) (*WhoAmIResponse, error) {
	//  a universal way to know the identity of a client
	// 		Send a signed message to /whoami route
	timestamp := time.Now().Unix()

	signedMessage := fmt.Sprintf("%d:%s", timestamp, base64.StdEncoding.EncodeToString(pubkey))
	signature := ed25519.Sign(privkey, []byte(signedMessage))

	payload := WhoAmIRequest{
		PublicKey: base64.StdEncoding.EncodeToString(pubkey),
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := http.Post("http://127.0.0.1:8080/api/whoami", "application/json", bytes.NewBuffer(jsonBody)) // PLACEHOLDER for global var
	if err != nil {
		return nil, fmt.Errorf("connect to controller: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whoami failed: HTTP %d", resp.StatusCode)
	}

	var clientStatus WhoAmIResponse
	if err := json.NewDecoder(resp.Body).Decode(&clientStatus); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &clientStatus, nil
}

type EnrollmentResponse struct {
	Hostname string      `json:"hostname,omitempty"`
	Status   AgentStatus `json:"status"`
	PubKey   string      `json:"pubkey,omitempty"`
	Profiles []string    `json:"profiles,omitempty"`
}

func Enroll(pubkey []byte, privkey []byte, hostname, secret string) (*EnrollmentResponse, int, error) {
	//  enroll an agent with the controller
	//  return of status and profiles determines run mode (waiting, idle, active, pullProfiles)
	msgBytes, err := json.Marshal(EnrollMessage{
		Hostname:    hostname,
		AdminSecret: secret,
		Timestamp:   time.Now().Unix(),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal message: %w", err)
	}

	signature := ed25519.Sign(privkey, msgBytes)

	payload, err := json.Marshal(EnrollmentRequest{
		PublicKey: base64.StdEncoding.EncodeToString(pubkey),
		Message:   base64.StdEncoding.EncodeToString(msgBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal payload: %w", err)
	}

	resp, err := http.Post("http://127.0.0.1:8080/api/enroll", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("connect to controller: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var dev EnrollmentResponse
		if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decoder response: %w", err)
		}
		return &dev, resp.StatusCode, nil

	case http.StatusNotModified:
		return nil, resp.StatusCode, nil

	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, fmt.Errorf("Failed to enroll with controller: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
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

func ValidateControllerMessage(controllerSignature string, controllerKey string, message []byte) error {
	publicKey, err := base64.StdEncoding.DecodeString(controllerKey)
	if err != nil {
		fmt.Printf("Error decoding controllers public key. %v\n", err)
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(controllerSignature)
	if err != nil {
		fmt.Printf("Error decoding controllers public key. %v\n", err)
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("Invalid length of controllers public key.")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("Invalid length of controllers signature.")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return errors.New("Verification of signature failed.")
	}

	return nil
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
