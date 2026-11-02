package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	// "path"
	// "path/filepath"
)

type Secrets struct {
	Pubkey  string `json:"pubkey"`
	Privkey string `json:"privkey"`
}

func main() {
	// privKey, pubKey, err := ed25519.GenerateKey(nil)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("privkey: %x\n", privKey)
	// fmt.Printf("pubkey: %x\n", pubKey)

	startup()
}

func startup() {
	// 1. Validate or Creata ed25519 key pair.
	keyPairValidation()

	// 2. Connect or Enroll with controller
	// 		Send a signed message to /whoami route
}

func keyPairValidation() {
	secretsFile := "./secrets.json"
	if _, err := os.Stat(secretsFile); err == nil {
		fileData, err := os.ReadFile(secretsFile)
		if err != nil {
			fmt.Printf("Error reading keyfile: %v\n", err)
			return
		}

		var keys Secrets
		err = json.Unmarshal(fileData, &keys)
		if err != nil {
			fmt.Printf("Error reading keys from JSON keyfile data %v\n", err)
			return
		}

		// Decode from base64 > ed25519
		pubKey, errpub := base64.StdEncoding.DecodeString(keys.Pubkey)
		privKey, errpriv := base64.StdEncoding.DecodeString(keys.Privkey)
		if errpub != nil || errpriv != nil {
			fmt.Println("Error decoden Base64 endoded keys from file")
			return
		}

		fmt.Printf("Successfully read keyfile: \n")
		fmt.Printf("pubkey: %x\nprivkey: %x\n", pubKey, privKey)

	} else if errors.Is(err, os.ErrNotExist) {
		privKey, pubKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		// Encode to bas64
		s := Secrets{
			Pubkey:  base64.StdEncoding.EncodeToString(pubKey),
			Privkey: base64.StdEncoding.EncodeToString(privKey),
		}

		jsonData, err := json.MarshalIndent(s, "", " ")
		if err != nil {
			fmt.Printf("Error converting generated keypair to JSON: %v\n", err)
			return
		}

		err = os.WriteFile("./secrets.json", jsonData, 0644)
		if err != nil {
			fmt.Printf("Error creating keypair: %v\n", err)
		}

	} else {
		fmt.Errorf("Problem during daemon startup, could not verify key pair.")
		panic(err)
	}

}
