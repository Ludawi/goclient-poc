package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"go.yaml.in/yaml/v4"
)

const (
	secretsFile      = "secrets.yml"
	maxTimestampSkew = 5 * time.Minute
)

var devicesMu sync.Mutex

type Secrets struct {
	EnrollPassword string `yaml:"enroll_password"`
	SecretKey      string `yaml:"secret_key"`
	PublicKey      string `yaml:"public_key"`
}

type EnrollRequest struct {
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type EnrollMessage struct {
	Hostname       string `json:"hostname"`
	EnrollPassword string `json:"enroll_Password"`
	Timestamp      int64  `json:"timestamp"`
}

var (
	serverPrivKey   ed25519.PrivateKey
	serverPubKeyB64 string
)

func loadServerKeys() error {
	s, err := loadSecrets()
	if err != nil {
		return fmt.Errorf("load secrets: %v\n", err)
	}

	raw, err := base64.StdEncoding.DecodeString(s.SecretKey)
	if err != nil {
		return fmt.Errorf("secret_key is not valid base64: %w", err)
	}

	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(raw)
	default:
		return fmt.Errorf("secret must decode to %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}

	derived := priv.Public().(ed25519.PublicKey)

	if s.PublicKey != "" {
		configured, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil || !bytes.Equal(configured, derived) {
			return fmt.Errorf("public_key in %s does not match secret_key", secretsFile)
		}
	}

	serverPrivKey = priv
	serverPubKeyB64 = base64.StdEncoding.EncodeToString(derived)
	return nil
}

func loadSecrets() (*Secrets, error) {
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return nil, err
	}

	var s Secrets
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	return &s, nil
}

func writeDevice(w http.ResponseWriter, status int, dev *Device) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(dev)
}

func enrollHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//  --- decode key, message, signature ----
	pubBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}
	msgBytes, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		http.Error(w, "Invalid message encoding", http.StatusBadRequest)
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}

	//  Verify signature
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), msgBytes, sigBytes) {
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	var msg EnrollMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil || msg.Hostname == "" {
		http.Error(w, "Invalid message content", http.StatusBadRequest)
		return
	}

	// Replay protection
	skew := time.Since(time.Unix(msg.Timestamp, 0))
	if skew > maxTimestampSkew || skew < -maxTimestampSkew {
		http.Error(w, "Timestamp out of range", http.StatusUnauthorized)
		return
	}

	//  Verify enrollment secret
	secrets, err := loadSecrets()
	if err != nil {
		fmt.Printf("failed to load secrets %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if secrets.EnrollPassword == "" ||
		subtle.ConstantTimeCompare([]byte(msg.EnrollPassword), []byte(secrets.EnrollPassword)) != 1 {
		http.Error(w, "Invalid enroll password", http.StatusUnauthorized)
		return
	}

	//  --- device lookup, devices file actions ---
	devicesMu.Lock() // file lock for data integrity
	defer devicesMu.Unlock()

	devices, err := loadDevices()
	if err != nil {
		fmt.Printf("failed to load devices %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	idx := findByHostname(devices, msg.Hostname)
	switch {
	case idx < 0:
		dev, err := createDevice(msg.Hostname, req.PublicKey)
		if err != nil {
			fmt.Printf("createDevice: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		writeDevice(w, http.StatusCreated, dev)

	case devices[idx].PubKey == req.PublicKey:
		writeDevice(w, http.StatusNotModified, &devices[idx])

	default:
		dev, err := renewPublicKey(msg.Hostname, req.PublicKey)
		if err != nil {
			fmt.Printf("renewPublicKey: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		writeDevice(w, http.StatusOK, dev)
	}
}

// WhoAmIRequest matches the structure sent by the client
type WhoAmIRequest struct {
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"Timestamp"`
	Signature string `json:"Signature"`
}

type AgentStatus string

const (
	StatusUnknown     AgentStatus = "unknown"
	StatusActive      AgentStatus = "active"
	StatusInactive    AgentStatus = "inactive"
	StatusWaiting     AgentStatus = "waiting"
	StatusDeactivated AgentStatus = "deactivated"
)

func whoAmIHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "This is a GET request")

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		var req WhoAmIRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PublicKey == "" {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		devicesMu.Lock()
		devices, err := loadDevices()
		devicesMu.Unlock()
		if err != nil {
			fmt.Printf("failed to load devices: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		idx := findByPubKey(devices, req.PublicKey)
		if idx < 0 {
			// Unknown public key
			json.NewEncoder(w).Encode(map[string]AgentStatus{"status": StatusUnknown})
			return
		}

		d := devices[idx]
		json.NewEncoder(w).Encode(DeviceInfo{
			Hostname: d.Hostname,
			Status:   d.Status,
			PubKey:   d.PubKey,
			Profiles: d.Profiles,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type SignatureResponse struct {
	Timestamp int64  `json:"timestamp"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func signatureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ts := time.Now().Unix()
	sig := ed25519.Sign(serverPrivKey, []byte(strconv.FormatInt(ts, 10)))

	response := SignatureResponse{
		Timestamp: ts,
		PublicKey: serverPubKeyB64,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	if err := loadServerKeys(); err != nil {
		fmt.Printf("failed to load server keys: %v\n", err)
		os.Exit(1)
	}
	http.HandleFunc("/api/whoami", whoAmIHandler)
	http.HandleFunc("/api/signature", signatureHandler)
	http.HandleFunc("/api/enroll", enrollHandler)

	fmt.Println("Server starting on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
