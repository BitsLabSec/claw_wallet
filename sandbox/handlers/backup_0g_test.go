package handlers

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	gc "sandbox/internals/crypto"
	"sandbox/internals/signer"
)

func TestBuildZeroGRecoveryArtifactsLockedRejectsMissingState(t *testing.T) {
	prevUID := boundUid
	prevMasterPubKey := masterPubKey
	prevShare2 := localShare2
	prevShare3 := encShare3
	prevSEK := append([]byte(nil), sekKey...)
	t.Cleanup(func() {
		boundUid = prevUID
		masterPubKey = prevMasterPubKey
		localShare2 = prevShare2
		encShare3 = prevShare3
		sekKey = prevSEK
	})

	boundUid = ""
	masterPubKey = "02abcd"
	localShare2 = signer.EncryptedShare{Cipher: "c2", IV: "iv2", Salt: "salt2", Iterations: 1}
	encShare3 = signer.EncryptedShare{Cipher: "c3", IV: "iv3", Salt: "salt3", Iterations: 1}
	sekKey = bytes.Repeat([]byte{0x11}, 32)

	_, err := buildZeroGRecoveryArtifactsLocked(time.Unix(1_700_000_000, 0).UTC())
	if err == nil {
		t.Fatal("expected buildZeroGRecoveryArtifactsLocked to fail")
	}
	if !strings.Contains(err.Error(), "uid") {
		t.Fatalf("expected uid validation error, got %v", err)
	}
}

func TestBuildZeroGRecoveryArtifactsLockedEncryptsSharesWithSEK(t *testing.T) {
	prevUID := boundUid
	prevMasterPubKey := masterPubKey
	prevShare2 := localShare2
	prevShare3 := encShare3
	prevSEK := append([]byte(nil), sekKey...)
	t.Cleanup(func() {
		boundUid = prevUID
		masterPubKey = prevMasterPubKey
		localShare2 = prevShare2
		encShare3 = prevShare3
		sekKey = prevSEK
	})

	boundUid = "UID-demo"
	masterPubKey = "0288cc"
	localShare2 = signer.EncryptedShare{Cipher: "cipher-two", IV: "iv-two", Salt: "salt-two", Iterations: 600000}
	encShare3 = signer.EncryptedShare{Cipher: "cipher-three", IV: "iv-three", Salt: "salt-three", Iterations: 600000}
	sekKey = bytes.Repeat([]byte{0x42}, 32)

	got, err := buildZeroGRecoveryArtifactsLocked(time.Unix(1_700_000_123, 0).UTC())
	if err != nil {
		t.Fatalf("buildZeroGRecoveryArtifactsLocked returned error: %v", err)
	}
	if got.UIDHashHex == "" {
		t.Fatal("expected uid hash to be populated")
	}
	if got.Share2.CommitmentHex == "" || got.Share3.CommitmentHex == "" {
		t.Fatal("expected share commitments to be populated")
	}
	if bytes.Equal(got.Share2.Ciphertext, got.Share3.Ciphertext) {
		t.Fatal("expected share2/share3 ciphertext to differ")
	}

	plain2, err := gc.DecryptData(sekKey, got.Share2.Ciphertext, got.Share2.Nonce)
	if err != nil {
		t.Fatalf("share2 decrypt failed: %v", err)
	}
	var payload2 struct {
		UID            string                `json:"uid"`
		MasterPubKey   string                `json:"master_pub_key"`
		Kind           string                `json:"kind"`
		EncryptedShare signer.EncryptedShare `json:"encrypted_share"`
	}
	if err := json.Unmarshal(plain2, &payload2); err != nil {
		t.Fatalf("share2 payload json invalid: %v", err)
	}
	if payload2.UID != "UID-demo" || payload2.Kind != "share2" {
		t.Fatalf("unexpected share2 payload: %+v", payload2)
	}
	if payload2.EncryptedShare.Cipher != "cipher-two" {
		t.Fatalf("unexpected share2 ciphertext payload: %+v", payload2.EncryptedShare)
	}
}

func TestHandleZeroGRecoveryBackupReturnsConflictWhenWalletStateUnavailable(t *testing.T) {
	prevUID := boundUid
	prevMasterPubKey := masterPubKey
	prevShare2 := localShare2
	prevShare3 := encShare3
	prevSEK := append([]byte(nil), sekKey...)
	t.Cleanup(func() {
		boundUid = prevUID
		masterPubKey = prevMasterPubKey
		localShare2 = prevShare2
		encShare3 = prevShare3
		sekKey = prevSEK
	})

	boundUid = ""
	masterPubKey = ""
	localShare2 = signer.EncryptedShare{}
	encShare3 = signer.EncryptedShare{}
	sekKey = nil

	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallet/backup/0g", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()

	handleZeroGRecoveryBackup(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleZeroGRecoveryBackupRejectsInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallet/backup/0g", bytes.NewReader([]byte(`{`)))
	rr := httptest.NewRecorder()

	handleZeroGRecoveryBackup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleZeroGRecoveryBackupUploadsAndRegisters(t *testing.T) {
	prevUID := boundUid
	prevMasterPubKey := masterPubKey
	prevShare2 := localShare2
	prevShare3 := encShare3
	prevSEK := append([]byte(nil), sekKey...)
	prevNewUploader := newZeroGBackupUploader
	prevNewRegistrar := newRecoveryVaultRegistrar
	prevRPC := os.Getenv("CLAY_0G_STORAGE_RPC")
	prevIndexer := os.Getenv("CLAY_0G_STORAGE_INDEXER")
	prevVault := os.Getenv("CLAY_0G_RECOVERY_VAULT_ADDRESS")
	t.Cleanup(func() {
		boundUid = prevUID
		masterPubKey = prevMasterPubKey
		localShare2 = prevShare2
		encShare3 = prevShare3
		sekKey = prevSEK
		newZeroGBackupUploader = prevNewUploader
		newRecoveryVaultRegistrar = prevNewRegistrar
		_ = os.Setenv("CLAY_0G_STORAGE_RPC", prevRPC)
		_ = os.Setenv("CLAY_0G_STORAGE_INDEXER", prevIndexer)
		_ = os.Setenv("CLAY_0G_RECOVERY_VAULT_ADDRESS", prevVault)
	})

	boundUid = "UID-demo"
	sekKey = bytes.Repeat([]byte{0x24}, 32)
	wallet, err := (&signer.Signer{}).CreateWallet(strings.Repeat("24", 32))
	if err != nil {
		t.Fatalf("CreateWallet failed: %v", err)
	}
	masterPubKey = wallet.MasterPubKey
	localShare2 = wallet.Share2
	encShare3 = wallet.Share3

	if err := os.Setenv("CLAY_0G_STORAGE_RPC", "https://evmrpc-testnet.0g.ai"); err != nil {
		t.Fatalf("set rpc env failed: %v", err)
	}
	if err := os.Setenv("CLAY_0G_STORAGE_INDEXER", "https://indexer-storage-testnet-turbo.0g.ai"); err != nil {
		t.Fatalf("set indexer env failed: %v", err)
	}
	if err := os.Setenv("CLAY_0G_RECOVERY_VAULT_ADDRESS", "0x1111111111111111111111111111111111111111"); err != nil {
		t.Fatalf("set vault env failed: %v", err)
	}

	var uploadedKinds []string
	newZeroGBackupUploader = func(cfg zeroGStorageConfig, evmPrivateKeyHex string) (zeroGBackupUploader, error) {
		if cfg.RPCURL == "" || cfg.IndexerURL == "" {
			t.Fatalf("expected rpc/indexer config, got %+v", cfg)
		}
		if evmPrivateKeyHex == "" {
			t.Fatal("expected derived private key")
		}
		return zeroGBackupUploaderFunc(func(kind string, blob []byte) (zeroGUploadResult, error) {
			uploadedKinds = append(uploadedKinds, kind)
			return zeroGUploadResult{
				RootHash: "0xroot-" + kind,
				TxHash:   "0xtx-" + kind,
			}, nil
		}), nil
	}

	var registered *zeroGBackupRegistration
	newRecoveryVaultRegistrar = func(cfg recoveryVaultConfig, evmPrivateKeyHex string) (recoveryVaultRegistrar, error) {
		return recoveryVaultRegistrarFunc(func(req zeroGBackupRegistration) (string, error) {
			registered = &req
			return "0xvaulttx", nil
		}), nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallet/backup/0g", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()

	handleZeroGRecoveryBackup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(uploadedKinds) != 2 || uploadedKinds[0] != "share2" || uploadedKinds[1] != "share3" {
		t.Fatalf("unexpected upload order: %+v", uploadedKinds)
	}
	if registered == nil {
		t.Fatal("expected registration payload")
	}

	var resp zeroGBackupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json invalid: %v", err)
	}
	if resp.VaultTxHash != "0xvaulttx" {
		t.Fatalf("expected vault tx hash, got %+v", resp)
	}
	if resp.Share2.RootHash != "0xroot-share2" || resp.Share3.RootHash != "0xroot-share3" {
		t.Fatalf("unexpected share roots: %+v", resp)
	}
}

func TestDeriveZeroGEVMPrivateKeyHexFromLocalState(t *testing.T) {
	sharePIN := "123456"
	wallet, err := (&signer.Signer{}).CreateWallet(sharePIN)
	if err != nil {
		t.Fatalf("CreateWallet failed: %v", err)
	}
	sek := bytes.Repeat([]byte{0x55}, 32)
	sekPIN := strings.Repeat("55", 32)
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resharded, err := signer.New(wallet.Share3, sharePIN, priv, wallet.MasterPubKey)
	if err != nil {
		t.Fatalf("New signer failed: %v", err)
	}
	req := &signer.SignRequest{EncShare1: wallet.Share2}
	_, _ = sek, sekPIN
	_ = req

	got, err := deriveZeroGEVMPrivateKeyHex(wallet.MasterPubKey, wallet.Share2, wallet.Share3, bytes.Repeat([]byte{0x31}, 32))
	if err == nil {
		t.Fatalf("expected deriveZeroGEVMPrivateKeyHex to fail with mismatched sek, got %q", got)
	}
	resharded.Wipe()
}
