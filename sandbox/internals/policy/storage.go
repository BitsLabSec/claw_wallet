package policy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	gc "sandbox/internals/crypto"
	"strings"
)

const encryptedPolicyEnvelopeVersion = "claw_policy_encrypted_v1"

var ErrPolicyEncryptionUnavailable = errors.New("policy encryption unavailable")

type encryptedPolicyEnvelope struct {
	Version       string `json:"version"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type policyIdentityRecord struct {
	WrappedSEK string `json:"wrapped_sek,omitempty"`
	AgentToken string `json:"agent_token,omitempty"`
}

type policyWrappedSEKRecord struct {
	WrappedSEK string `json:"wrapped_sek,omitempty"`
	AgentToken string `json:"agent_token,omitempty"`
}

func policyIdentityPath() string {
	identityPath := strings.TrimSpace(os.Getenv("IDENTITY_PATH"))
	if identityPath == "" {
		return "identity.json"
	}
	return identityPath
}

func policyWrappedSEKPath(identityPath string) string {
	identityPath = strings.TrimSpace(identityPath)
	if identityPath == "" {
		identityPath = "identity.json"
	}
	return filepath.Join(filepath.Dir(identityPath), "wrapped_sek.json")
}

func persistPolicyWrappedSEKRecord(path, wrappedSEK, agentToken string) error {
	wrappedSEK = strings.TrimSpace(wrappedSEK)
	if wrappedSEK == "" {
		return nil
	}
	payload, err := json.MarshalIndent(policyWrappedSEKRecord{
		WrappedSEK: wrappedSEK,
		AgentToken: strings.TrimSpace(agentToken),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode wrapped_sek payload: %w", err)
	}
	return atomicWritePolicy(path, payload)
}

func loadPolicyWrappedSEKRecord(path string) (policyWrappedSEKRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyWrappedSEKRecord{}, err
	}
	var record policyWrappedSEKRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return policyWrappedSEKRecord{}, fmt.Errorf("parse wrapped_sek file: %w", err)
	}
	return record, nil
}

func unwrapPolicySEK(identityPath, wrappedSEK, agentToken string) ([]byte, error) {
	wrappedSEK = strings.TrimSpace(wrappedSEK)
	if wrappedSEK == "" {
		return nil, fmt.Errorf("%w: wrapped_sek is empty", ErrPolicyEncryptionUnavailable)
	}
	agentToken = strings.TrimSpace(agentToken)
	if agentToken == "" {
		agentToken = strings.TrimSpace(os.Getenv("AGENT_TOKEN"))
	}
	kek := gc.DeriveKEK(agentToken, identityPath)
	sek, err := gc.UnwrapSEK(wrappedSEK, kek)
	if err != nil {
		return nil, fmt.Errorf("unwrap policy sek: %w", err)
	}
	return sek, nil
}

func loadPolicySEK(identityPath string) ([]byte, error) {
	data, err := os.ReadFile(identityPath)
	if err == nil {
		var id policyIdentityRecord
		if err := json.Unmarshal(data, &id); err != nil {
			return nil, fmt.Errorf("parse identity for policy encryption: %w", err)
		}
		if strings.TrimSpace(id.WrappedSEK) != "" {
			if err := persistPolicyWrappedSEKRecord(policyWrappedSEKPath(identityPath), id.WrappedSEK, id.AgentToken); err != nil {
				return nil, err
			}
			return unwrapPolicySEK(identityPath, id.WrappedSEK, id.AgentToken)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read identity for policy encryption: %w", err)
	}

	record, err := loadPolicyWrappedSEKRecord(policyWrappedSEKPath(identityPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: identity.json does not contain wrapped_sek and wrapped_sek.json not found", ErrPolicyEncryptionUnavailable)
		}
		return nil, err
	}
	return unwrapPolicySEK(identityPath, record.WrappedSEK, record.AgentToken)
}

func decodeStoredPolicyBytes(data []byte) ([]byte, bool, error) {
	var envelope encryptedPolicyEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return append([]byte(nil), data...), false, nil
	}
	if envelope.Version != encryptedPolicyEnvelopeVersion || envelope.NonceHex == "" || envelope.CiphertextHex == "" {
		return append([]byte(nil), data...), false, nil
	}

	nonce, err := hex.DecodeString(envelope.NonceHex)
	if err != nil {
		return nil, true, fmt.Errorf("decode policy nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(envelope.CiphertextHex)
	if err != nil {
		return nil, true, fmt.Errorf("decode policy ciphertext: %w", err)
	}
	sek, err := loadPolicySEK(policyIdentityPath())
	if err != nil {
		return nil, true, err
	}
	plain, err := gc.DecryptData(sek, ciphertext, nonce)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt policy payload: %w", err)
	}
	return plain, true, nil
}

func ReadStoredPolicyBytes(path string) ([]byte, error) {
	data, _, err := readStoredPolicyBytes(path)
	return data, err
}

func readStoredPolicyBytes(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	plain, encrypted, err := decodeStoredPolicyBytes(data)
	if err != nil {
		return nil, encrypted, err
	}
	return plain, encrypted, nil
}

func WriteStoredPolicyBytes(path string, plain []byte) error {
	sek, err := loadPolicySEK(policyIdentityPath())
	if err != nil {
		return err
	}
	ciphertext, nonce, err := gc.EncryptData(sek, plain)
	if err != nil {
		return fmt.Errorf("encrypt policy payload: %w", err)
	}
	payload, err := json.MarshalIndent(encryptedPolicyEnvelope{
		Version:       encryptedPolicyEnvelopeVersion,
		NonceHex:      hex.EncodeToString(nonce),
		CiphertextHex: hex.EncodeToString(ciphertext),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode encrypted policy payload: %w", err)
	}
	return atomicWritePolicy(path, payload)
}
