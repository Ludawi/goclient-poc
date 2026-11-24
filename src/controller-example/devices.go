package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const devicesFile = "devices.yml"

type Device struct {
	ClientID string      `json:"client_id"`
	Hostname string      `json:"hostname"`
	Status   AgentStatus `json:"status"`
	PubKey   string      `json:"pubkey"`
	Profiles []string    `json:"profiles"`
}

// DeviceInfo ==  public view of a device
type DeviceInfo struct {
	Hostname string      `json:"hostname"`
	Status   AgentStatus `json:"status"`
	PubKey   string      `json:"pubkey"`
	Profiles []string    `json:"profiles"`
}

// NOTE: the functions below do not lock. The caller must hold devicesMu
// (see main.go) so lookup + modify + save is one atomic operation.

func loadDevices() ([]Device, error) {
	data, err := os.ReadFile(devicesFile)
	if errors.Is(err, os.ErrNotExist) {
		return []Device{}, nil
	}
	if err != nil {
		return nil, err
	}
	var devices []Device
	if len(data) == 0 {
		return []Device{}, nil
	}
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, fmt.Errorf("parse %s: %w", devicesFile, err)
	}
	return devices, nil
}

// saveDevices writes atomically (temp file + rename) so a crash can't corrupt the file.
func saveDevices(devices []Device) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(devicesFile), ".devices-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), devicesFile)
}

// findByHostname returns the index of the device with the hostname, or -1.
func findByHostname(devices []Device, hostname string) int {
	for i, d := range devices {
		if d.Hostname == hostname {
			return i
		}
	}
	return -1
}

// findByPubKey returns the index of the first device with the public key, or -1.
func findByPubKey(devices []Device, pubKey string) int {
	for i, d := range devices {
		if d.PubKey == pubKey {
			return i
		}
	}
	return -1
}

// uniqueClientID returns hostname, or hostname0x0 ... hostname0xFF if taken.
func uniqueClientID(devices []Device, hostname string) (string, error) {
	taken := make(map[string]bool, len(devices))
	for _, d := range devices {
		taken[d.ClientID] = true
	}
	if !taken[hostname] {
		return hostname, nil
	}
	for i := 0; i <= 0xFF; i++ {
		id := fmt.Sprintf("%s0x%X", hostname, i)
		if !taken[id] {
			return id, nil
		}
	}
	return "", fmt.Errorf("no free client_id left for hostname %q", hostname)
}

// createDevice appends a new device (status "waiting", no profiles) and saves the file.
func createDevice(hostname, pubKey string) (*Device, error) {
	devices, err := loadDevices()
	if err != nil {
		return nil, err
	}
	id, err := uniqueClientID(devices, hostname)
	if err != nil {
		return nil, err
	}
	dev := Device{
		ClientID: id,
		Hostname: hostname,
		Status:   StatusWaiting,
		PubKey:   pubKey,
		Profiles: []string{},
	}
	devices = append(devices, dev)
	if err := saveDevices(devices); err != nil {
		return nil, err
	}
	return &dev, nil
}

// renewPublicKey sets (replaces or creates) the public key of the device with the hostname.
func renewPublicKey(hostname, pubKey string) (*Device, error) {
	devices, err := loadDevices()
	if err != nil {
		return nil, err
	}
	i := findByHostname(devices, hostname)
	if i < 0 {
		return nil, fmt.Errorf("device with hostname %q not found", hostname)
	}
	devices[i].PubKey = pubKey
	if err := saveDevices(devices); err != nil {
		return nil, err
	}
	return &devices[i], nil
}
