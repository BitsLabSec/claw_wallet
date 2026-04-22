package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	gc "sandbox/internals/crypto"
	"testing"
)

func TestLoadSEKFromIdentityOrWrappedFileHandlesEmptyAgentToken(t *testing.T) {
	t.Setenv("AGENT_TOKEN", "")

	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.json")

	sek, err := gc.GenerateSEK()
	if err != nil {
		t.Fatalf("generate sek: %v", err)
	}
	kek := gc.DeriveKEK("", identityPath)
	wrappedSEK, err := gc.WrapSEK(sek, kek)
	if err != nil {
		t.Fatalf("wrap sek: %v", err)
	}

	identityPayload, err := json.Marshal(map[string]any{
		"wrapped_sek": wrappedSEK,
	})
	if err != nil {
		t.Fatalf("marshal identity payload: %v", err)
	}
	if err := os.WriteFile(identityPath, identityPayload, 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	loaded, err := LoadSEKFromIdentityOrWrappedFile(identityPath)
	if err != nil {
		t.Fatalf("load sek: %v", err)
	}
	if string(loaded) != string(sek) {
		t.Fatalf("expected loaded sek to match original, got %x want %x", loaded, sek)
	}

	wrappedPath := WrappedSEKPath(identityPath)
	if _, err := os.Stat(wrappedPath); err != nil {
		t.Fatalf("expected wrapped_sek.json to be created, stat failed: %v", err)
	}
}
