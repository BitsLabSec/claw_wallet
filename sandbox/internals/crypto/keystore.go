// sandbox/internals/crypto/keystore.go
// Manages the Share Encryption Key (SHARE_ENC_KEY) which is separate from AGENT_TOKEN.
//
// Security model:
//   - SHARE_ENC_KEY is a random 32-byte key generated once at wallet initialization.
//   - It is never stored in plaintext. Instead, it is wrapped using a KEK (Key Encryption Key).
//   - KEK is derived from: AGENT_TOKEN + stable machine id + identity directory.
//   - An agent that knows AGENT_TOKEN but runs on a different machine or uses a different wallet data root
//     cannot unwrap the SEK.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const shareEncKeyLen = 32

func normalizeIdentityDir(identityPath string) string {
	identityPath = strings.TrimSpace(identityPath)
	if identityPath == "" {
		identityPath = "identity.json"
	}
	if abs, err := filepath.Abs(identityPath); err == nil {
		identityPath = abs
	}
	return filepath.Clean(filepath.Dir(identityPath))
}

func readMachineID() string {
	switch runtime.GOOS {
	case "linux":
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if data, err := os.ReadFile(path); err == nil {
				if v := strings.TrimSpace(string(data)); v != "" {
					return v
				}
			}
		}
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if !strings.Contains(line, "IOPlatformUUID") {
					continue
				}
				parts := strings.Split(line, "=")
				if len(parts) < 2 {
					continue
				}
				v := strings.TrimSpace(parts[len(parts)-1])
				v = strings.Trim(v, "\"")
				if v != "" {
					return v
				}
			}
		}
	case "windows":
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if !strings.Contains(line, "MachineGuid") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) > 0 {
					return fields[len(fields)-1]
				}
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("CLAY_MACHINE_ID")); v != "" {
		return v
	}
	return "unknown-machine-id"
}

// MachineFingerprint returns a stable value bound to the host machine and wallet data root.
func MachineFingerprint(identityPath string) string {
	machineID := readMachineID()
	identityDir := normalizeIdentityDir(identityPath)
	fp := fmt.Sprintf("clay-fp-v2|%s|%s|%s", runtime.GOOS, machineID, identityDir)
	h := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(h[:16])
}

// DeriveKEK derives the Key Encryption Key from agentToken + machine fingerprint.
// The resulting key is used only to wrap/unwrap the Share Encryption Key (SEK).
func DeriveKEK(agentToken, identityPath string) []byte {
	fp := MachineFingerprint(identityPath)
	info := []byte("CLAY-KEK-v1|" + fp)
	h := hkdf.New(sha256.New, []byte(agentToken), []byte("CLAY-KEK-SALT"), info)
	kek := make([]byte, 32)
	h.Read(kek)
	return kek
}

// WrapSEK encrypts a 32-byte Share Encryption Key using the KEK (AES-GCM).
// Returns: hex(nonce + ciphertext)
func WrapSEK(sek, kek []byte) (string, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, sek, nil)
	combined := append(nonce, ct...)
	return hex.EncodeToString(combined), nil
}

// UnwrapSEK decrypts a wrapped Share Encryption Key using the KEK.
func UnwrapSEK(wrappedHex string, kek []byte) ([]byte, error) {
	data, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return nil, fmt.Errorf("UnwrapSEK: invalid hex: %w", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns+16 {
		return nil, fmt.Errorf("UnwrapSEK: data too short")
	}
	nonce := data[:ns]
	ct := data[ns:]
	sek, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("UnwrapSEK: AEAD failed (wrong token or machine): %w", err)
	}
	return sek, nil
}

// GenerateSEK creates a new random 32-byte Share Encryption Key.
func GenerateSEK() ([]byte, error) {
	sek := make([]byte, shareEncKeyLen)
	if _, err := rand.Read(sek); err != nil {
		return nil, fmt.Errorf("GenerateSEK: %w", err)
	}
	return sek, nil
}
