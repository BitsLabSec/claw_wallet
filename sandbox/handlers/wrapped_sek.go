package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	gc "sandbox/internals/crypto"
	"sandbox/internals/utils"
	"strings"
)

type wrappedSEKRecord struct {
	WrappedSEK string `json:"wrapped_sek,omitempty"`
	AgentToken string `json:"agent_token,omitempty"`
}

func WrappedSEKPath(identityPath string) string {
	identityPath = strings.TrimSpace(identityPath)
	if identityPath == "" {
		identityPath = "identity.json"
	}
	return filepath.Join(filepath.Dir(identityPath), "wrapped_sek.json")
}

func EnsureWrappedSEKFile(identityPath, wrappedSEK, agentToken string) error {
	wrappedSEK = strings.TrimSpace(wrappedSEK)
	if wrappedSEK == "" {
		return nil
	}
	payload, err := json.MarshalIndent(wrappedSEKRecord{
		WrappedSEK: wrappedSEK,
		AgentToken: strings.TrimSpace(agentToken),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode wrapped_sek payload: %w", err)
	}
	return utils.AtomicWrite(WrappedSEKPath(identityPath), payload)
}

func LoadSEKFromIdentityOrWrappedFile(identityPath string) ([]byte, error) {
	if sek, agentToken, ok, err := loadSEKFromIdentity(identityPath); err != nil {
		return nil, err
	} else if ok {
		if err := EnsureWrappedSEKFile(identityPath, sek.WrappedSEK, agentToken); err != nil {
			return nil, err
		}
		return unwrapSEK(identityPath, sek.WrappedSEK, agentToken)
	}

	record, err := loadWrappedSEKRecord(WrappedSEKPath(identityPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("identity.json and wrapped_sek.json do not contain wrapped_sek")
		}
		return nil, err
	}
	if strings.TrimSpace(record.WrappedSEK) == "" {
		return nil, errors.New("wrapped_sek.json does not contain wrapped_sek")
	}
	return unwrapSEK(identityPath, record.WrappedSEK, record.AgentToken)
}

func loadSEKFromIdentity(identityPath string) (wrappedSEKRecord, string, bool, error) {
	data, err := os.ReadFile(identityPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wrappedSEKRecord{}, "", false, nil
		}
		return wrappedSEKRecord{}, "", false, fmt.Errorf("read identity for sek restore: %w", err)
	}
	var id struct {
		WrappedSEK string `json:"wrapped_sek,omitempty"`
		AgentToken string `json:"agent_token,omitempty"`
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return wrappedSEKRecord{}, "", false, fmt.Errorf("parse identity for sek restore: %w", err)
	}
	if strings.TrimSpace(id.WrappedSEK) == "" {
		return wrappedSEKRecord{}, strings.TrimSpace(id.AgentToken), false, nil
	}
	return wrappedSEKRecord{WrappedSEK: id.WrappedSEK, AgentToken: id.AgentToken}, strings.TrimSpace(id.AgentToken), true, nil
}

func loadWrappedSEKRecord(path string) (wrappedSEKRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wrappedSEKRecord{}, err
	}
	var rec wrappedSEKRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return wrappedSEKRecord{}, fmt.Errorf("parse wrapped_sek file: %w", err)
	}
	return rec, nil
}

func unwrapSEK(identityPath, wrappedSEK, agentToken string) ([]byte, error) {
	wrappedSEK = strings.TrimSpace(wrappedSEK)
	if wrappedSEK == "" {
		return nil, errors.New("wrapped_sek is empty")
	}
	agentToken = strings.TrimSpace(agentToken)
	if agentToken == "" {
		agentToken = strings.TrimSpace(env("AGENT_TOKEN", ""))
	}
	kek := gc.DeriveKEK(agentToken, identityPath)
	sek, err := gc.UnwrapSEK(wrappedSEK, kek)
	if err != nil {
		return nil, fmt.Errorf("sek unwrap failed: %w", err)
	}
	return sek, nil
}
