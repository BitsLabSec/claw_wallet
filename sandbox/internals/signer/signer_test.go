package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

func TestGenerateKeysAndSplit(t *testing.T) {
	// 创建一个临时的 Signer 壳子
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	s := &Signer{
		sandboxPriv: priv,
	}

	pin := "123456"

	// 1. 生成并切片
	resp, err := s.CreateWallet(pin)
	if err != nil {
		t.Fatalf("CreateWallet failed: %v", err)
	}

	if resp.UID == "" {
		t.Error("UID should not be empty")
	}
	if resp.MasterPubKey == "" {
		t.Error("MasterPubKey should not be empty")
	}

	// 2. 验证恢复能力
	// 假设我们在 Sandbox 内部持有了 Share 3 作为自己的持久化身份
	s2, err := New(resp.Share3, pin, priv, resp.MasterPubKey)
	if err != nil {
		t.Fatalf("Failed to instantiate new Signer from Share 3: %v", err)
	}

	// 使用从 Backend 拿回来的 Share 1 进行政策签名等验证
	isValid := s2.ValidatePolicyUpdate(pin, resp.Share1)
	if !isValid {
		t.Error("Failed to reconstruct private key and validate matching MasterPubKey")
	}
}

func TestDerivationPaths(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	// Test BIP32 SECP256K1
	_, err := DeriveSecp256k1(seed, "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("DeriveSecp256k1 failed: %v", err)
	}

	// Test SLIP-10 Ed25519
	// 注意 SLIP-10 Ed25519 仅支持 Hardened path
	_, err = DeriveEd25519(seed, "m/44'/501'/0'/0'")
	if err != nil {
		t.Fatalf("DeriveEd25519 hardened failed: %v", err)
	}

	_, err = DeriveEd25519(seed, "m/44'/501'/0'/0/0")
	if err == nil {
		t.Fatalf("DeriveEd25519 should fail cleanly with non-hardened path")
	}
}
func TestEthereumSigning(t *testing.T) {
	// Sample seed
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	derived, _ := DeriveSecp256k1(seed, "m/44'/60'/0'/0/0")

	// Sign a message
	payload := []byte("hello")
	res, err := signEthereum(derived, payload, "personal_sign")
	if err != nil {
		t.Fatalf("signEthereum failed: %v", err)
	}

	if len(res.SignatureHex) != 132 { // 0x + 65*2
		t.Errorf("expected 132 chars signature, got %d", len(res.SignatureHex))
	}
	if res.From == "" {
		t.Error("expected address, got empty")
	}
}

func TestPersonalSignGuardrails(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	derived, _ := DeriveSecp256k1(seed, "m/44'/60'/0'/0/0")

	if _, err := signEthereum(derived, []byte{0xff, 0xfe, 0xfd}, "personal_sign"); err == nil {
		t.Fatalf("expected invalid UTF-8 payload to be rejected")
	}

	if _, err := signEthereum(derived, []byte("0x02f8700180843b9aca00847735940082520894d8da6bf26964af9d7eed9e03e53415d37aa96045880180c0"), "personal_sign"); err == nil {
		t.Fatalf("expected hex-like payload to be rejected")
	}

	if _, err := signEthereum(derived, []byte("Sign in to CLAY"), "personal_sign"); err != nil {
		t.Fatalf("expected normal text payload to pass guardrails: %v", err)
	}
}

func TestStrictPlainTextKeywordBlacklist(t *testing.T) {
	if err := ValidateStrictPlainTextPayload([]byte("Please transfer ownership of this wallet"), []string{"transfer ownership"}); err == nil {
		t.Fatalf("expected keyword blacklist to reject dangerous phrase")
	}

	if err := ValidateStrictPlainTextPayload([]byte("Sign in to CLAY"), []string{"transfer ownership"}); err != nil {
		t.Fatalf("expected safe phrase to pass strict plain text validation: %v", err)
	}
}

func TestValidateSuiPersonalSignMessage(t *testing.T) {
	payload := append([]byte{0x03, 0x00, 0x00}, []byte("hello sui")...)
	if err := ValidateSuiPersonalSignMessage(payload, []string{"transfer ownership"}); err != nil {
		t.Fatalf("expected valid sui personal_sign payload to pass: %v", err)
	}

	blockedPayload := append([]byte{0x03, 0x00, 0x00}, []byte("please transfer ownership")...)
	if err := ValidateSuiPersonalSignMessage(blockedPayload, []string{"transfer ownership"}); err == nil {
		t.Fatalf("expected blocked keyword to reject sui personal_sign payload")
	}
}

func TestAssessAuditability(t *testing.T) {
	evmAssessment, err := AssessAuditability(&SignRequest{
		Chain:       "ethereum",
		SignMode:    "transaction",
		BuilderKind: "native_transfer",
		To:          "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
		AmountWei:   "1000000000000000000",
		Data:        "0x",
	})
	if err != nil {
		t.Fatalf("expected evm auditability assessment to succeed: %v", err)
	}
	if !evmAssessment.Enforceable || !evmAssessment.Auditable {
		t.Fatalf("expected evm tx to be auditable, got %+v", evmAssessment)
	}

	rawHashAssessment, err := AssessAuditability(&SignRequest{
		Chain:        "ethereum",
		SignMode:     "raw_hash",
		TxPayloadHex: "0x" + strings.Repeat("11", 32),
	})
	if err != nil {
		t.Fatalf("expected raw hash assessment to succeed: %v", err)
	}
	if !rawHashAssessment.Enforceable || rawHashAssessment.Auditable {
		t.Fatalf("expected raw hash to be blind, got %+v", rawHashAssessment)
	}

	solanaAssessment, err := AssessAuditability(&SignRequest{
		Chain:        "solana",
		SignMode:     "transaction",
		TxPayloadHex: "0100ff10",
	})
	if err != nil {
		t.Fatalf("expected solana assessment to succeed: %v", err)
	}
	if solanaAssessment.Enforceable {
		t.Fatalf("expected raw solana tx to remain non-enforceable until structured builder exists, got %+v", solanaAssessment)
	}

	suiAssessment, err := AssessAuditability(&SignRequest{
		Chain:        "sui",
		SignMode:     "personal_sign",
		TxPayloadHex: "0x03000068656c6c6f20737569",
	})
	if err != nil {
		t.Fatalf("expected sui personal_sign assessment to succeed: %v", err)
	}
	if !suiAssessment.Enforceable || !suiAssessment.Auditable {
		t.Fatalf("expected sui personal_sign to be auditable, got %+v", suiAssessment)
	}
}

func TestValidateSignRequest(t *testing.T) {
	req := &SignRequest{
		Chain:        "solana",
		SignMode:     "transaction",
		TxPayloadHex: "00ff10",
	}
	if err := validateSignRequest(req); err != nil {
		t.Fatalf("expected valid request, got err: %v", err)
	}

	badReq := &SignRequest{
		Chain:        "solana",
		SignMode:     "typed_data",
		TxPayloadHex: "00ff10",
	}
	if err := validateSignRequest(badReq); err == nil {
		t.Fatalf("expected unsupported sign_mode to fail")
	}

	structuredReq := &SignRequest{
		Chain:       "ethereum",
		SignMode:    "transaction",
		BuilderKind: "native_transfer",
		To:          "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
		AmountWei:   "1",
		Data:        "0x",
	}
	if err := validateSignRequest(structuredReq); err != nil {
		t.Fatalf("expected structured transaction request to share the same interface contract: %v", err)
	}

	baseReq := &SignRequest{
		Chain:        "base",
		SignMode:     "personal_sign",
		TxPayloadHex: hex.EncodeToString([]byte("hello base")),
	}
	if err := validateSignRequest(baseReq); err != nil {
		t.Fatalf("expected base to be treated as an EVM chain: %v", err)
	}

	kiteReq := &SignRequest{
		Chain:        "kite",
		SignMode:     "personal_sign",
		TxPayloadHex: hex.EncodeToString([]byte("hello kite")),
	}
	if err := validateSignRequest(kiteReq); err != nil {
		t.Fatalf("expected kite to be treated as an EVM chain: %v", err)
	}
}

func TestKiteIsEVMChainAndUsesEthereumDerivation(t *testing.T) {
	if !IsEVMChain("kite") {
		t.Fatalf("expected kite to be classified as EVM")
	}
	if got := defaultDerivationPath("kite", ""); got != "m/44'/60'/0'/0/0" {
		t.Fatalf("defaultDerivationPath(kite) = %q, want ethereum path", got)
	}
}

func TestTempoIsEVMChainAndUsesEthereumDerivation(t *testing.T) {
	if !IsEVMChain("tempo") {
		t.Fatalf("expected tempo to be classified as EVM")
	}
	if got := defaultDerivationPath("tempo", ""); got != "m/44'/60'/0'/0/0" {
		t.Fatalf("defaultDerivationPath(tempo) = %q, want ethereum path", got)
	}
}

func TestValidateSolanaPayload(t *testing.T) {
	if err := validateSolanaPayload([]byte("transfer 1 SOL"), "transaction"); err == nil {
		t.Fatalf("expected plain text transaction payload to be rejected")
	}
	if err := validateSolanaPayload([]byte{0x01, 0x00, 0xff, 0x10}, "transaction"); err != nil {
		t.Fatalf("expected binary transaction payload to pass: %v", err)
	}
	if err := validateSolanaPayload([]byte("hello solana"), "personal_sign"); err != nil {
		t.Fatalf("expected text personal_sign payload to pass: %v", err)
	}
}

func TestValidateSuiIntentPayload(t *testing.T) {
	txPayload := append([]byte{0x00, 0x00, 0x00}, []byte{0x99, 0x88, 0x77}...)
	if err := validateSuiIntentPayload(txPayload, "transaction"); err != nil {
		t.Fatalf("expected transaction intent payload to pass: %v", err)
	}
	if err := validateSuiIntentPayload(txPayload, "personal_sign"); err == nil {
		t.Fatalf("expected wrong intent scope to fail")
	}

	msgPayload := append([]byte{0x03, 0x00, 0x00}, []byte("hello")...)
	if err := validateSuiIntentPayload(msgPayload, "personal_sign"); err != nil {
		t.Fatalf("expected personal intent payload to pass: %v", err)
	}
}

func TestCreateWalletDefaultSigningAddressesMatchReturnedAddresses(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	s := &Signer{sandboxPriv: priv}

	resp, err := s.CreateWallet("123456")
	if err != nil {
		t.Fatalf("CreateWallet failed: %v", err)
	}

	activeSigner, err := New(resp.Share3, "123456", priv, resp.MasterPubKey)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	evmSig, err := activeSigner.Sign(&SignRequest{
		Chain:        "ethereum",
		SignMode:     "personal_sign",
		TxPayloadHex: hex.EncodeToString([]byte("hello")),
		EncShare1:    resp.Share1,
	})
	if err != nil {
		t.Fatalf("ethereum Sign failed: %v", err)
	}
	if evmSig.From != resp.Addresses["ethereum"] {
		t.Fatalf("ethereum default address mismatch: got %s want %s", evmSig.From, resp.Addresses["ethereum"])
	}
	if resp.Addresses["monad"] != resp.Addresses["ethereum"] {
		t.Fatalf("monad should mirror ethereum address: got %s want %s", resp.Addresses["monad"], resp.Addresses["ethereum"])
	}
	if resp.Addresses["tempo"] != resp.Addresses["ethereum"] {
		t.Fatalf("tempo should mirror ethereum address: got %s want %s", resp.Addresses["tempo"], resp.Addresses["ethereum"])
	}

	solSig, err := activeSigner.Sign(&SignRequest{
		Chain:        "solana",
		SignMode:     "transaction",
		TxPayloadHex: "0100ff10",
		EncShare1:    resp.Share1,
	})
	if err != nil {
		t.Fatalf("solana Sign failed: %v", err)
	}
	solPub, err := hex.DecodeString(solSig.From)
	if err != nil {
		t.Fatalf("failed to decode solana public key: %v", err)
	}
	if got := base58.Encode(solPub); got != resp.Addresses["solana"] {
		t.Fatalf("solana default address mismatch: got %s want %s", got, resp.Addresses["solana"])
	}

	suiSig, err := activeSigner.Sign(&SignRequest{
		Chain:        "sui",
		SignMode:     "transaction",
		TxPayloadHex: "000000998877",
		EncShare1:    resp.Share1,
	})
	if err != nil {
		t.Fatalf("sui Sign failed: %v", err)
	}
	suiPub, err := hex.DecodeString(suiSig.From)
	if err != nil {
		t.Fatalf("failed to decode sui public key: %v", err)
	}
	suiInput := append([]byte{0x00}, suiPub...)
	suiHash := blake2b.Sum256(suiInput)
	suiAddr := "0x" + hex.EncodeToString(suiHash[:])
	if suiAddr != resp.Addresses["sui"] {
		t.Fatalf("sui default address mismatch: got %s want %s", suiAddr, resp.Addresses["sui"])
	}

	bitcoinSig, err := activeSigner.Sign(&SignRequest{
		Chain:        "bitcoin",
		SignMode:     "transaction",
		TxPayloadHex: "deadbeef",
		EncShare1:    resp.Share1,
	})
	if err != nil {
		t.Fatalf("bitcoin Sign failed: %v", err)
	}
	if bitcoinSig.From != resp.Addresses["bitcoin"] {
		t.Fatalf("bitcoin default address mismatch: got %s want %s", bitcoinSig.From, resp.Addresses["bitcoin"])
	}
	if strings.EqualFold(bitcoinSig.From, resp.MasterPubKey) {
		t.Fatalf("bitcoin address should not equal master public key: %s", bitcoinSig.From)
	}
}

func TestProvisionedSignerCanSignWithWrappedShare2(t *testing.T) {
	sandboxPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	resp, err := (&Signer{}).CreateWallet("123456")
	if err != nil {
		t.Fatalf("CreateWallet failed: %v", err)
	}

	activeSigner, err := NewProvisioned(resp.Share1, "123456", sandboxPriv, resp.MasterPubKey)
	if err != nil {
		t.Fatalf("NewProvisioned failed: %v", err)
	}

	wrappedShare2, nonceHex := wrapEncryptedShareForSandbox(t, sandboxPriv.PublicKey(), resp.Share2)
	res, err := activeSigner.Sign(&SignRequest{
		Chain:         "ethereum",
		SignMode:      "personal_sign",
		TxPayloadHex:  hex.EncodeToString([]byte("hello provisioned wallet")),
		WrappedShare2: wrappedShare2,
		Share2Nonce:   nonceHex,
	})
	if err != nil {
		t.Fatalf("provisioned Sign failed: %v", err)
	}
	if res.From != resp.Addresses["ethereum"] {
		t.Fatalf("provisioned address mismatch: got %s want %s", res.From, resp.Addresses["ethereum"])
	}
}

// TestMasterChainSignMatchesMasterPubKey verifies that signing with Chain="master"
// produces a signature verifiable against masterPubKey (btcec.PrivKeyFromBytes(seed)),
// NOT against the BIP32-derived Ethereum key.
func TestMasterChainSignMatchesMasterPubKey(t *testing.T) {
	pin := "testpin"
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	s := &Signer{sandboxPriv: priv}

	wallet, err := s.CreateWallet(pin)
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}

	s2, err := New(wallet.Share3, pin, priv, wallet.MasterPubKey)
	if err != nil {
		t.Fatalf("New signer: %v", err)
	}

	// The message hash simulating a bind challenge.
	hash := sha256.Sum256([]byte("claw_wallet:testuid:bind:testuserid:nonce123"))
	hashHex := hex.EncodeToString(hash[:])

	res, err := s2.Sign(&SignRequest{
		Chain:           "master",
		SignMode:        "raw_hash",
		TxPayloadHex:    hashHex,
		EncShare1:       wallet.Share2, // Share2 stored as local share2 in phase-1
		ConfirmedByUser: true,
	})
	if err != nil {
		t.Fatalf("Sign with master chain: %v", err)
	}

	// The signature must be 65 bytes (R||S||V) = 130 hex chars + "0x" prefix.
	if len(res.SignatureHex) != 132 {
		t.Errorf("expected 132 hex chars, got %d: %s", len(res.SignatureHex), res.SignatureHex)
	}

	// The masterPubKey corresponds to btcec.PrivKeyFromBytes(seed).
	// The ETH derived key is DeriveSecp256k1(seed, "m/44'/60'/0'/0/0").
	// They must produce different addresses — confirming we did NOT use the BIP32 ETH key.
	if res.From == wallet.Addresses["ethereum"] {
		t.Errorf("master chain signing must NOT use the BIP32 ETH derived key; got matching address %s", res.From)
	}

	t.Logf("master sign ok: sig=%s from=%s masterPubKey=%s ethAddr=%s",
		res.SignatureHex[:20]+"...", res.From, wallet.MasterPubKey, wallet.Addresses["ethereum"])
}

func wrapEncryptedShareForSandbox(t *testing.T, sandboxPub *ecdh.PublicKey, share EncryptedShare) (string, string) {
	t.Helper()

	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	secret, err := serverPriv.ECDH(sandboxPub)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	hk := hkdf.New(sha256.New, secret, nil, []byte("CLAY-SHARE2-WRAP"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, aesKey); err != nil {
		t.Fatalf("hkdf read failed: %v", err)
	}

	plain, err := json.Marshal(share)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM failed: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce generation failed: %v", err)
	}
	cipherText := gcm.Seal(nil, nonce, plain, nil)
	envelope := append(serverPriv.PublicKey().Bytes(), cipherText...)
	return hex.EncodeToString(envelope), hex.EncodeToString(nonce)
}
