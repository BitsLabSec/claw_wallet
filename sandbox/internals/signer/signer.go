// sandbox/internals/signer/signer.go
package signer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sandbox/internals/crypto"
	"strings"
	"unicode"

	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/shamir"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

const (
	defaultPBKDF2Iterations     = 600000
	defaultEvmDerivationPath    = "m/44'/60'/0'/0/0"
	defaultSolanaDerivationPath = "m/44'/501'/0'/0'"
	defaultSuiDerivationPath    = "m/44'/784'/0'/0'/0'"
	defaultTronDerivationPath   = "m/44'/195'/0'/0/0"
)

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

type EvmDecodedIntent struct {
	TxType   string
	To       string
	ValueWei string
	DataHex  string
}

func DecodeEvmSigningPayloadIntent(txPayload []byte) (*EvmDecodedIntent, error) {
	if len(txPayload) == 0 {
		return nil, errors.New("empty tx payload")
	}

	txType := byte(0x00)
	rlpBody := txPayload
	if txPayload[0] < 0xc0 {
		txType = txPayload[0]
		if txType != 0x01 && txType != 0x02 {
			return nil, fmt.Errorf("unsupported typed tx prefix: 0x%02x", txType)
		}
		if len(txPayload) == 1 {
			return nil, errors.New("typed tx missing rlp body")
		}
		rlpBody = txPayload[1:]
	}

	var elems []rlp.RawValue
	if err := rlp.DecodeBytes(rlpBody, &elems); err != nil {
		return nil, fmt.Errorf("rlp decode failed: %w", err)
	}

	intent := &EvmDecodedIntent{
		TxType:   "legacy",
		To:       "",
		ValueWei: "0",
		DataHex:  "0x",
	}

	var toIdx, valueIdx, dataIdx int
	switch txType {
	case 0x00:
		if len(elems) != 6 && len(elems) != 9 {
			return nil, fmt.Errorf("legacy signing payload must have 6 or 9 rlp elements, got %d", len(elems))
		}
		toIdx, valueIdx, dataIdx = 3, 4, 5
	case 0x01:
		intent.TxType = "eip2930"
		if len(elems) != 8 {
			return nil, fmt.Errorf("eip2930 signing payload must have 8 rlp elements, got %d", len(elems))
		}
		toIdx, valueIdx, dataIdx = 4, 5, 6
	case 0x02:
		intent.TxType = "eip1559"
		if len(elems) != 9 {
			return nil, fmt.Errorf("eip1559 signing payload must have 9 rlp elements, got %d", len(elems))
		}
		toIdx, valueIdx, dataIdx = 5, 6, 7
	default:
		return nil, fmt.Errorf("unsupported evm tx type: 0x%02x", txType)
	}

	var toBytes []byte
	if err := rlp.DecodeBytes(elems[toIdx], &toBytes); err != nil {
		return nil, fmt.Errorf("decode to failed: %w", err)
	}
	if len(toBytes) == 0 {
		intent.To = ""
	} else {
		if len(toBytes) != 20 {
			return nil, fmt.Errorf("invalid to length: %d", len(toBytes))
		}
		intent.To = "0x" + hex.EncodeToString(toBytes)
	}

	var value big.Int
	if err := rlp.DecodeBytes(elems[valueIdx], &value); err != nil {
		return nil, fmt.Errorf("decode value failed: %w", err)
	}
	intent.ValueWei = value.String()

	var dataBytes []byte
	if err := rlp.DecodeBytes(elems[dataIdx], &dataBytes); err != nil {
		return nil, fmt.Errorf("decode data failed: %w", err)
	}
	intent.DataHex = "0x" + hex.EncodeToString(dataBytes)

	return intent, nil
}

type EncryptedShare struct {
	Cipher     string `json:"cipher"`
	IV         string `json:"iv"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations,omitempty"`
}

type SignRequest struct {
	Chain           string          `json:"chain"`     // ethereum, solana, sui, tron, aptos, bitcoin
	SignMode        string          `json:"sign_mode"` // transaction, personal_sign, typed_data, raw_hash
	DerivationPath  string          `json:"derivation_path,omitempty"`
	BuilderKind     string          `json:"builder_kind,omitempty"`
	To              string          `json:"to"`
	TokenContract   string          `json:"token_contract,omitempty"`
	AmountWei       string          `json:"amount_wei"`
	Data            string          `json:"data"`
	UID             string          `json:"uid"`
	ConfirmedByUser bool            `json:"confirmed_by_user,omitempty"`
	IsUserApproval  bool            `json:"is_user_approval,omitempty"`
	ApprovalID      string          `json:"approval_id,omitempty"`
	ExecutionToken  string          `json:"execution_token,omitempty"`
	EncShare1       EncryptedShare  `json:"enc_share1"`
	WrappedShare2   string          `json:"wrapped_share2_hex,omitempty"`
	Share2Nonce     string          `json:"share2_nonce_hex,omitempty"`
	TxPayloadHex    string          `json:"tx_payload_hex"`
	TypedData       json.RawMessage `json:"typed_data,omitempty"`
}

type SignResult struct {
	SignatureHex string `json:"signature_hex"`
	From         string `json:"from"`
	TxPayloadHex string `json:"tx_payload_hex,omitempty"`
	RawTxHex     string `json:"raw_tx_hex,omitempty"`
	BuilderKind  string `json:"builder_kind,omitempty"`
}

type AuditabilityAssessment struct {
	Enforceable bool   `json:"enforceable"`
	Auditable   bool   `json:"auditable"`
	Reason      string `json:"reason,omitempty"`
}

func normalizeSignMode(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "transaction"
	}
	return mode
}

func isTransactionLikeSignMode(mode string) bool {
	switch normalizeSignMode(mode) {
	case "transaction", "swap", "bridge":
		return true
	default:
		return false
	}
}

func IsEVMChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "avalanche", "linea", "zksync", "monad", "tempo", "kite", "sepolia":
		return true
	default:
		return false
	}
}

func hasStructuredTransactionIntent(req *SignRequest) bool {
	if req == nil {
		return false
	}
	if !isTransactionLikeSignMode(req.SignMode) {
		return false
	}
	if strings.TrimSpace(req.BuilderKind) == "" {
		return false
	}
	if strings.TrimSpace(req.To) == "" || strings.TrimSpace(req.AmountWei) == "" {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(req.BuilderKind)) {
	case "native_transfer":
		return IsEVMChain(req.Chain) || strings.EqualFold(req.Chain, "solana") || strings.EqualFold(req.Chain, "sui")
	case "erc20_transfer":
		return IsEVMChain(req.Chain) && strings.TrimSpace(req.TokenContract) != ""
	case "sol_transfer":
		return strings.EqualFold(req.Chain, "solana")
	case "spl_transfer":
		return strings.EqualFold(req.Chain, "solana") && strings.TrimSpace(req.TokenContract) != ""
	case "sui_transfer":
		return strings.EqualFold(req.Chain, "sui")
	default:
		return false
	}
}

func defaultDerivationPath(chain, path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}

	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "master":
		return "" // no BIP32 derivation; raw seed is used directly
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "avalanche", "linea", "zksync", "monad", "tempo", "kite", "sepolia":
		return defaultEvmDerivationPath
	case "solana":
		return defaultSolanaDerivationPath
	case "sui":
		return defaultSuiDerivationPath
	case "tron":
		return defaultTronDerivationPath
	default:
		return path
	}
}

func isPrintableTextPayload(payload []byte) bool {
	if len(payload) == 0 || !utf8.Valid(payload) {
		return false
	}
	hasVisible := false
	for _, r := range string(payload) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
		if !unicode.IsSpace(r) {
			hasVisible = true
		}
	}
	return hasVisible
}

func validateSignRequest(req *SignRequest) error {
	req.Chain = strings.ToLower(strings.TrimSpace(req.Chain))
	req.SignMode = normalizeSignMode(req.SignMode)

	switch req.Chain {
	case "master":
		// Signs directly with the raw seed key (btcec.PrivKeyFromBytes(seed)), which corresponds
		// to masterPubKey stored on the relay. Only raw_hash mode is supported.
		if req.SignMode != "raw_hash" {
			return fmt.Errorf("master chain only supports raw_hash sign_mode")
		}
		if strings.TrimSpace(req.TxPayloadHex) == "" {
			return errors.New("tx_payload_hex is required for master chain signing")
		}
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "avalanche", "linea", "zksync", "monad", "tempo", "kite", "sepolia":
		switch req.SignMode {
		case "transaction", "swap", "bridge", "personal_sign", "raw_hash":
			if strings.TrimSpace(req.TxPayloadHex) == "" && !(isTransactionLikeSignMode(req.SignMode) && hasStructuredTransactionIntent(req)) {
				return errors.New("tx_payload_hex is required for this ethereum sign_mode")
			}
		case "typed_data":
			if len(req.TypedData) == 0 {
				return errors.New("typed_data is required for sign_mode=typed_data")
			}
		default:
			return fmt.Errorf("unsupported ethereum sign_mode: %s", req.SignMode)
		}
	case "solana":
		switch req.SignMode {
		case "transaction", "swap", "bridge", "personal_sign":
			if strings.TrimSpace(req.TxPayloadHex) == "" && !(isTransactionLikeSignMode(req.SignMode) && hasStructuredTransactionIntent(req)) {
				return errors.New("tx_payload_hex is required for solana")
			}
		default:
			return fmt.Errorf("unsupported solana sign_mode: %s", req.SignMode)
		}
	case "sui":
		switch req.SignMode {
		case "transaction", "swap", "bridge", "personal_sign":
			if strings.TrimSpace(req.TxPayloadHex) == "" && !(isTransactionLikeSignMode(req.SignMode) && hasStructuredTransactionIntent(req)) {
				return errors.New("tx_payload_hex is required for sui")
			}
		default:
			return fmt.Errorf("unsupported sui sign_mode: %s", req.SignMode)
		}
	case "tron":
		if req.SignMode != "transaction" {
			return fmt.Errorf("unsupported %s sign_mode: %s", req.Chain, req.SignMode)
		}
		if strings.TrimSpace(req.TxPayloadHex) == "" {
			return fmt.Errorf("tx_payload_hex is required for %s", req.Chain)
		}
	case "aptos", "ton", "bitcoin":
		if req.SignMode != "transaction" {
			return fmt.Errorf("unsupported %s sign_mode: %s", req.Chain, req.SignMode)
		}
		if strings.TrimSpace(req.TxPayloadHex) == "" {
			return fmt.Errorf("tx_payload_hex is required for %s", req.Chain)
		}
	default:
		return fmt.Errorf("unsupported curve: %s", req.Chain)
	}

	return nil
}

func validateSolanaPayload(payload []byte, mode string) error {
	if len(payload) == 0 {
		return errors.New("solana payload cannot be empty")
	}
	if mode == "transaction" && isPrintableTextPayload(payload) {
		return errors.New("solana transaction payload must be serialized bytes, not plain text")
	}
	if mode == "personal_sign" && !isPrintableTextPayload(payload) {
		return errors.New("solana personal_sign payload must be valid printable text")
	}
	return nil
}

// suiPersonalSignIntentPrefix 为 Sui personal_sign 的 intent 头: [scope=PersonalMessage | version=0x00 | app_id=0x00]
var suiPersonalSignIntentPrefix = []byte{0x03, 0x00, 0x00}

// EnsureSuiPersonalSignIntentPrefix 若 payload 无 intent 前缀则自动添加，兼容外部只传纯消息的场景
func EnsureSuiPersonalSignIntentPrefix(payload []byte) []byte {
	if len(payload) >= 3 && payload[0] == 0x03 && payload[1] == 0x00 && payload[2] == 0x00 {
		return payload
	}
	out := make([]byte, len(suiPersonalSignIntentPrefix)+len(payload))
	copy(out, suiPersonalSignIntentPrefix)
	copy(out[len(suiPersonalSignIntentPrefix):], payload)
	return out
}

func validateSuiIntentPayload(payload []byte, mode string) error {
	if len(payload) < 4 {
		return errors.New("sui payload must include 3-byte intent header and body")
	}
	if payload[1] != 0x00 || payload[2] != 0x00 {
		return errors.New("sui intent version/app id must be 0x00/0x00")
	}
	expectedScope := byte(0x00)
	if mode == "personal_sign" {
		expectedScope = 0x03
	}
	if payload[0] != expectedScope {
		return fmt.Errorf("invalid sui intent scope: got 0x%02x", payload[0])
	}
	return nil
}

func AssessAuditability(req *SignRequest) (AuditabilityAssessment, error) {
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	mode := normalizeSignMode(req.SignMode)

	switch mode {
	case "typed_data":
		if chain == "ethereum" {
			return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "typed_data"}, nil
		}
	case "personal_sign":
		payload, err := decodeHex(req.TxPayloadHex)
		if err != nil {
			return AuditabilityAssessment{}, fmt.Errorf("invalid tx_payload_hex: %w", err)
		}
		if chain == "sui" {
			if err := validateSuiIntentPayload(payload, "personal_sign"); err != nil {
				return AuditabilityAssessment{}, err
			}
			if isPrintableTextPayload(payload[3:]) {
				return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "plain_text"}, nil
			}
			return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "personal_sign payload is not plain text"}, nil
		}
		if isPrintableTextPayload(payload) {
			return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "plain_text"}, nil
		}
		return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "personal_sign payload is not plain text"}, nil
	case "raw_hash":
		return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "raw hash signing is inherently blind"}, nil
	case "transaction", "swap", "bridge":
		if strings.TrimSpace(req.TxPayloadHex) == "" {
			if hasStructuredTransactionIntent(req) {
				return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "structured_" + strings.ToLower(strings.TrimSpace(req.BuilderKind))}, nil
			}
			return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "missing auditable transaction payload"}, nil
		}

		switch chain {
		case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "avalanche", "linea", "zksync", "monad", "tempo", "kite", "sepolia":
			txBytes, err := decodeHex(req.TxPayloadHex)
			if err != nil {
				return AuditabilityAssessment{}, fmt.Errorf("invalid tx_payload_hex: %w", err)
			}
			intent, err := DecodeEvmSigningPayloadIntent(txBytes)
			if err != nil {
				return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "evm transaction could not be decoded"}, nil
			}
			if strings.TrimSpace(intent.To) == "" {
				return AuditabilityAssessment{Enforceable: true, Auditable: false, Reason: "contract creation is not auditable yet"}, nil
			}
			return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "decoded_evm_transaction"}, nil
		case "solana", "sui":
			if strings.TrimSpace(req.To) != "" && strings.TrimSpace(req.AmountWei) != "" {
				return AuditabilityAssessment{Enforceable: true, Auditable: true, Reason: "structured_intent"}, nil
			}
			return AuditabilityAssessment{
				Enforceable: false,
				Auditable:   false,
				Reason:      chain + " raw transaction decoding is not yet human-readable; prefer structured builder",
			}, nil
		}
	}

	return AuditabilityAssessment{Enforceable: false, Auditable: false, Reason: "auditability not implemented for this request shape"}, nil
}

type CreateWalletResponse struct {
	UID          string            `json:"uid"`
	MasterPubKey string            `json:"master_pub_key"`
	Share1       EncryptedShare    `json:"share1"`
	Share2       EncryptedShare    `json:"share2"`
	Share3       EncryptedShare    `json:"share3"`
	Address      string            `json:"address"`
	Addresses    map[string]string `json:"addresses"`
}

type Signer struct {
	share3         []byte
	localEncShare1 *EncryptedShare
	agentToken     []byte
	sandboxPriv    *ecdh.PrivateKey
	masterPubKey   []byte // 钱包的主公钥，作为该 Sandbox 的终极身份 ID
}

// New creates a Signer and critically validates it against the expected master public key.
func New(encShare3 EncryptedShare, pin string, priv *ecdh.PrivateKey, expectedPubHex string) (*Signer, error) {
	p, err := decryptShareWithPIN(pin, encShare3)
	if err != nil {
		return nil, fmt.Errorf("share3 decryption failed: %w", err)
	}

	// 2. Validate Identity - 无论以后换什么 share，PIN 拆出来的东西必须能对上这个公钥
	// 这是为了防止黑客用自己的 share 注入你的 Sandbox 内存。
	// 这里演示 secp256k1 的验证（Share 3 第一个字节是 Shamir 索引，后面是种子片）
	// 注意：真正重构需要 2 份，这里先记录主公钥。
	expectedPub, err := decodeHex(expectedPubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid expected public key hex: %w", err)
	}

	return &Signer{
		share3:       p,
		agentToken:   []byte(pin),
		sandboxPriv:  priv,
		masterPubKey: expectedPub,
	}, nil
}

// NewProvisioned creates a Signer for a phase2 provisioned wallet where sandbox
// keeps encrypted Share 1 locally and fetches wrapped Share 2 during signing.
func NewProvisioned(encShare1 EncryptedShare, pin string, priv *ecdh.PrivateKey, expectedPubHex string) (*Signer, error) {
	share1, err := decryptShareWithPIN(pin, encShare1)
	if err != nil {
		return nil, fmt.Errorf("share1 decryption failed: %w", err)
	}
	zeroize(share1)

	expectedPub, err := decodeHex(expectedPubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid expected public key hex: %w", err)
	}

	localShare1 := encShare1
	return &Signer{
		localEncShare1: &localShare1,
		agentToken:     []byte(pin),
		sandboxPriv:    priv,
		masterPubKey:   expectedPub,
	}, nil
}

// ValidatePolicyUpdate verifies that providing this PIN can indeed reconstruct the private key
// that matches our masterPubKey.
func (s *Signer) ValidatePolicyUpdate(pin string, encShare1 EncryptedShare) bool {
	// 试图用这个 PIN 解密 Share 1
	shareA, err := s.decryptShare1WithPIN(pin, encShare1)
	if err != nil {
		return false
	}

	// 试图重构私钥并推导公钥进行比对
	sharesSlice := [][]byte{shareA, s.share3}
	seed, err := shamir.Combine(sharesSlice)
	if err != nil {
		return false
	}
	defer zeroize(seed)

	// 只要能推导出主公钥，就证明这个 PIN 是合法的，且政策修改意图来自持有 PIN 的人
	_, pub := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(pub.SerializeCompressed()) == hex.EncodeToString(s.masterPubKey)
}

func (s *Signer) Wipe() {
	zeroize(s.share3)
	zeroize(s.agentToken)
	s.localEncShare1 = nil
	s.sandboxPriv = nil
}

func (s *Signer) VerifyPIN(pin string) bool {
	return string(s.agentToken) == pin
}

// SignChallenge signs a raw challenge string using the reconstructed private key.
// This is used for authenticating policy updates.
func (s *Signer) SignChallenge(challenge string, share1, share2 *EncryptedShare) (string, error) {
	// Reconstruct private key using provided shares
	s1, err := s.decryptShare1WithPIN(string(s.agentToken), *share1)
	if err != nil {
		return "", fmt.Errorf("share1 decrypt failed: %w", err)
	}
	s2, err := s.decryptShare1WithPIN(string(s.agentToken), *share2)
	if err != nil {
		return "", fmt.Errorf("share2 decrypt failed: %w", err)
	}

	sharesSlice := [][]byte{s1, s2}
	seed, err := shamir.Combine(sharesSlice)
	if err != nil {
		return "", err
	}
	defer zeroize(seed)

	priv, _ := btcec.PrivKeyFromBytes(seed)
	hash := sha256.Sum256([]byte(challenge))
	sig := ecdsa.Sign(priv, hash[:])
	return hex.EncodeToString(sig.Serialize()), nil
}

// CreateWallet generates a new private key and splits it into 3 SSS shards,
// each encrypted with the provided PIN.
func (s *Signer) CreateWallet(pin string) (*CreateWalletResponse, error) {
	// 1. Generate 32-byte seed
	seed := make([]byte, 32)
	if _, err := io.ReadFull(crypto_rand.Reader, seed); err != nil {
		return nil, err
	}
	defer zeroize(seed)

	return buildWalletResponseFromSeed(seed, pin)
}

func buildWalletResponseFromSeed(seed []byte, pin string) (*CreateWalletResponse, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed is required")
	}

	// 2. Get Public Key and Address
	_, pub := btcec.PrivKeyFromBytes(seed)
	masterPubHex := hex.EncodeToString(pub.SerializeCompressed())

	// 3. SSS Split (2-of-3)
	// shamir.Split returns a [][]byte
	shards, err := shamir.Split(seed, 3, 2)
	if err != nil {
		return nil, err
	}

	// 4. Encrypt all shards with PIN
	var encShards []EncryptedShare
	for _, shard := range shards {
		// Hashicorp vault shamir already includes the index in the first byte
		data := shard

		salt := make([]byte, 16)
		io.ReadFull(crypto_rand.Reader, salt)

		key := crypto.DeriveKeyFromPasswordWithIterations([]byte(pin), salt, defaultPBKDF2Iterations)
		cipherText, iv, _ := crypto.EncryptData(key, data)

		encShards = append(encShards, EncryptedShare{
			Cipher:     hex.EncodeToString(cipherText),
			IV:         hex.EncodeToString(iv),
			Salt:       hex.EncodeToString(salt),
			Iterations: defaultPBKDF2Iterations,
		})
	}

	// We expect 3 shards
	if len(encShards) < 3 {
		return nil, fmt.Errorf("unexpected number of shards: %d", len(encShards))
	}

	uid := fmt.Sprintf("UID-%s", hex.EncodeToString(seed[:4]))

	evmSeed, err := DeriveSecp256k1(seed, defaultEvmDerivationPath)
	if err != nil {
		return nil, err
	}
	_, evmPub := btcec.PrivKeyFromBytes(evmSeed)
	ethAddr := pubKeyToEthAddress(evmPub)

	solanaSeed, err := DeriveEd25519(seed, defaultSolanaDerivationPath)
	if err != nil {
		return nil, err
	}
	solPriv := ed25519.NewKeyFromSeed(solanaSeed)
	solPub := solPriv.Public().(ed25519.PublicKey)
	solAddr := base58.Encode(solPub) // Solana uses base58 encoding of Ed25519 pubkey

	suiSeed, err := DeriveEd25519(seed, defaultSuiDerivationPath)
	if err != nil {
		return nil, err
	}
	suiPriv := ed25519.NewKeyFromSeed(suiSeed)
	suiPub := suiPriv.Public().(ed25519.PublicKey)

	// Sui uses blake2b of flag(0x00 for ed25519) + pubkey
	suiInput := append([]byte{0x00}, suiPub...)
	suiHash := blake2b.Sum256(suiInput)
	suiAddr := "0x" + hex.EncodeToString(suiHash[:]) // Sui uses hex of blake2b hash
	tronAddr := pubKeyToTronAddress(pub)
	bitcoinAddr := pubKeyToBitcoinAddress(pub)

	return &CreateWalletResponse{
		UID:          uid,
		MasterPubKey: masterPubHex,
		Share1:       encShards[0],
		Share2:       encShards[1],
		Share3:       encShards[2],
		Address:      ethAddr,
		Addresses: map[string]string{
			"ethereum": ethAddr,
			"monad":    ethAddr,
			"tempo":    ethAddr,
			"solana":   solAddr,
			"sui":      suiAddr,
			"tron":     tronAddr,
			"bitcoin":  bitcoinAddr,
		},
	}, nil
}

func (s *Signer) ReshardLocalToPIN(newPIN, wrappedShare2, share2Nonce string) (*CreateWalletResponse, error) {
	if s.localEncShare1 != nil {
		return nil, errors.New("reshard flow is only available for local share3-backed wallets")
	}
	if strings.TrimSpace(newPIN) == "" {
		return nil, errors.New("new pin is required")
	}
	if len(s.share3) <= 1 {
		return nil, errors.New("local share3 is unavailable")
	}
	share2, err := s.decryptWrappedShare(wrappedShare2, share2Nonce)
	if err != nil {
		return nil, fmt.Errorf("share2 recovery failed: %w", err)
	}
	defer zeroize(share2)
	if len(share2) <= 1 {
		return nil, errors.New("decrypted share2 payload is invalid")
	}

	sharesSlice := [][]byte{share2, s.share3}
	seed, err := shamir.Combine(sharesSlice)
	if err != nil {
		return nil, err
	}
	defer zeroize(seed)

	if len(s.masterPubKey) > 0 {
		_, pub := btcec.PrivKeyFromBytes(seed)
		if !bytes.Equal(pub.SerializeCompressed(), s.masterPubKey) {
			return nil, errors.New("reconstructed key does not match expected master public key")
		}
	}
	return buildWalletResponseFromSeed(seed, newPIN)
}

func (s *Signer) ReshardProvisionedToPIN(newPIN, wrappedShare2, share2Nonce string) (*CreateWalletResponse, error) {
	if s.localEncShare1 == nil {
		return nil, errors.New("reshard flow requires local encrypted share1")
	}
	if strings.TrimSpace(newPIN) == "" {
		return nil, errors.New("new pin is required")
	}

	share1, err := s.decryptShare1WithPIN(string(s.agentToken), *s.localEncShare1)
	if err != nil {
		return nil, fmt.Errorf("share1 recovery failed: %w", err)
	}
	defer zeroize(share1)
	if len(share1) <= 1 {
		return nil, errors.New("decrypted share1 payload is invalid")
	}

	share2, err := s.decryptWrappedShare(wrappedShare2, share2Nonce)
	if err != nil {
		return nil, fmt.Errorf("share2 recovery failed: %w", err)
	}
	defer zeroize(share2)
	if len(share2) <= 1 {
		return nil, errors.New("decrypted share2 payload is invalid")
	}

	sharesSlice := [][]byte{share1, share2}
	seed, err := shamir.Combine(sharesSlice)
	if err != nil {
		return nil, err
	}
	defer zeroize(seed)

	if len(s.masterPubKey) > 0 {
		_, pub := btcec.PrivKeyFromBytes(seed)
		if !bytes.Equal(pub.SerializeCompressed(), s.masterPubKey) {
			return nil, errors.New("reconstructed key does not match expected master public key")
		}
	}
	return buildWalletResponseFromSeed(seed, newPIN)
}

func (s *Signer) Sign(req *SignRequest) (*SignResult, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	req.DerivationPath = defaultDerivationPath(req.Chain, req.DerivationPath)

	seed, err := s.ReconstructSeed(req)
	if err != nil {
		return nil, err
	}
	defer zeroize(seed)

	if len(s.masterPubKey) > 0 {
		_, pub := btcec.PrivKeyFromBytes(seed)
		if !bytes.Equal(pub.SerializeCompressed(), s.masterPubKey) {
			return nil, errors.New("reconstructed key does not match expected master public key")
		}
	}

	switch req.Chain {
	case "master":
		// Sign directly with the raw seed (btcec.PrivKeyFromBytes(seed)), matching masterPubKey.
		txBytes, err := decodeHex(req.TxPayloadHex)
		if err != nil {
			return nil, fmt.Errorf("invalid tx_payload_hex: %w", err)
		}
		return signEthereum(seed, txBytes, "raw_hash")
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "avalanche", "linea", "zksync", "monad", "tempo", "kite", "sepolia":
		derivedKey, err := DeriveSecp256k1(seed, req.DerivationPath)
		if err != nil {
			return nil, err
		}
		if req.SignMode == "typed_data" {
			return signEthereumTypedData(derivedKey, req.TypedData)
		}
		if strings.TrimSpace(req.TxPayloadHex) == "" && isTransactionLikeSignMode(req.SignMode) && hasStructuredTransactionIntent(req) {
			return nil, errors.New("structured transaction signing is not implemented yet; use the same /api/v1/tx/sign interface with auditable tx_payload_hex until secure builders land")
		}
		txBytes, err := decodeHex(req.TxPayloadHex)
		if err != nil {
			return nil, fmt.Errorf("invalid tx_payload_hex: %w", err)
		}
		return signEthereum(derivedKey, txBytes, req.SignMode)
	case "bitcoin":
		txBytes, err := decodeHex(req.TxPayloadHex)
		if err != nil {
			return nil, fmt.Errorf("invalid tx_payload_hex: %w", err)
		}
		derivedKey, err := DeriveSecp256k1(seed, req.DerivationPath)
		if err != nil {
			return nil, err
		}
		return signBitcoin(derivedKey, txBytes)
	case "solana", "sui", "aptos", "ton":
		if strings.TrimSpace(req.TxPayloadHex) == "" && isTransactionLikeSignMode(req.SignMode) && hasStructuredTransactionIntent(req) {
			return nil, fmt.Errorf("structured %s transaction signing is not implemented yet; secure builder support is still pending", req.Chain)
		}
		txBytes, err := decodeHex(req.TxPayloadHex)
		if err != nil {
			return nil, fmt.Errorf("invalid tx_payload_hex: %w", err)
		}
		derivedKey, err := DeriveEd25519(seed, req.DerivationPath)
		if err != nil {
			return nil, err
		}
		if req.Chain == "solana" {
			if err := validateSolanaPayload(txBytes, req.SignMode); err != nil {
				return nil, err
			}
			return signEd25519(derivedKey, txBytes)
		}
		if req.Chain == "sui" {
			if err := validateSuiIntentPayload(txBytes, req.SignMode); err != nil {
				return nil, err
			}
			return signSuiEd25519(derivedKey, txBytes)
		}
		if req.Chain == "tron" {
			return signTronTransaction(derivedKey, txBytes)
		}
		return signEd25519(derivedKey, txBytes)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", req.Chain)
	}
}

// ReconstructSeed rebuilds the wallet seed from the shares associated with the
// current signer session. Callers must zeroize the returned slice.
func (s *Signer) ReconstructSeed(req *SignRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("missing sign request")
	}

	var sharesSlice [][]byte
	var err error

	if s.localEncShare1 != nil {
		if req.WrappedShare2 == "" {
			return nil, errors.New("wrapped_share2_hex is required for provisioned wallet signing")
		}

		share1, err := s.decryptShare1WithPIN(string(s.agentToken), *s.localEncShare1)
		if err != nil {
			return nil, fmt.Errorf("share1 recovery failed: %w", err)
		}
		defer zeroize(share1)

		share2, err := s.decryptWrappedShare(req.WrappedShare2, req.Share2Nonce)
		if err != nil {
			return nil, fmt.Errorf("share2 recovery failed: %w", err)
		}
		defer zeroize(share2)

		if len(share1) <= 1 || len(share2) <= 1 {
			return nil, errors.New("decrypted share payload is invalid")
		}
		sharesSlice = append(sharesSlice, share1, share2)
	} else {
		var shareA []byte
		if req.WrappedShare2 != "" {
			shareA, err = s.decryptWrappedShare(req.WrappedShare2, req.Share2Nonce)
		} else if req.EncShare1.Cipher != "" {
			shareA, err = s.decryptShare1WithPIN(string(s.agentToken), req.EncShare1)
		} else {
			return nil, errors.New("neither WrappedShare2 nor EncShare1 was provided")
		}
		if err != nil {
			return nil, fmt.Errorf("share recovery failed: %w", err)
		}
		defer zeroize(shareA)

		if len(shareA) > 1 {
			sharesSlice = append(sharesSlice, shareA)
		} else {
			return nil, fmt.Errorf("shareA is invalid or too short: len=%d", len(shareA))
		}
		if len(s.share3) > 1 {
			sharesSlice = append(sharesSlice, s.share3)
		} else {
			return nil, fmt.Errorf("share3 is invalid or too short: len=%d", len(s.share3))
		}

		fmt.Printf("[DEBUG] Combining Shards: ShareA[%d] (len=%d), Share3[%d] (len=%d)\n",
			shareA[0], len(shareA[1:]), s.share3[0], len(s.share3[1:]))
	}

	seed, err := shamir.Combine(sharesSlice)
	if err != nil {
		return nil, err
	}
	if len(s.masterPubKey) > 0 {
		_, pub := btcec.PrivKeyFromBytes(seed)
		if !bytes.Equal(pub.SerializeCompressed(), s.masterPubKey) {
			zeroize(seed)
			return nil, errors.New("reconstructed key does not match expected master public key")
		}
	}
	return seed, nil
}

func (s *Signer) decryptShare1WithPIN(pin string, enc EncryptedShare) ([]byte, error) {
	return decryptShareWithPIN(pin, enc)
}

func decryptShareWithPIN(pin string, enc EncryptedShare) ([]byte, error) {
	salt, err := decodeHex(enc.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt decode err: %w", err)
	}
	iterations := enc.Iterations
	if iterations <= 0 {
		iterations = 100000
	}
	key := crypto.DeriveKeyFromPasswordWithIterations([]byte(pin), salt, iterations)
	cb, err := decodeHex(enc.Cipher)
	if err != nil {
		return nil, fmt.Errorf("cipher decode err: %w", err)
	}
	iv, err := decodeHex(enc.IV)
	if err != nil {
		return nil, fmt.Errorf("iv decode err: %w", err)
	}
	return crypto.DecryptData(key, cb, iv)
}

func UnwrapWrappedEncryptedShare(sandboxPriv *ecdh.PrivateKey, wrappedHex, nonceHex string) (EncryptedShare, error) {
	data, err := decodeHex(wrappedHex)
	if err != nil {
		return EncryptedShare{}, fmt.Errorf("wrapped hex err: %w", err)
	}
	nonce, err := decodeHex(nonceHex)
	if err != nil {
		return EncryptedShare{}, fmt.Errorf("nonce hex err: %w", err)
	}
	if len(data) < 66 {
		return EncryptedShare{}, errors.New("invalid envelope")
	}

	serverPubBytes := data[:65]
	ciphertext := data[65:]

	curve := ecdh.P256()
	serverPub, _ := curve.NewPublicKey(serverPubBytes)
	secret, _ := sandboxPriv.ECDH(serverPub)

	hk := hkdf.New(sha256.New, secret, nil, []byte("CLAY-SHARE2-WRAP"))
	aesKey := make([]byte, 32)
	io.ReadFull(hk, aesKey)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	innerJSON, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return EncryptedShare{}, err
	}

	var inner EncryptedShare
	if err := json.Unmarshal(innerJSON, &inner); err != nil {
		return EncryptedShare{}, err
	}
	return inner, nil
}

func (s *Signer) decryptWrappedShare(wrappedHex, nonceHex string) ([]byte, error) {
	inner, err := UnwrapWrappedEncryptedShare(s.sandboxPriv, wrappedHex, nonceHex)
	if err != nil {
		return nil, err
	}
	return s.decryptShare1WithPIN(string(s.agentToken), inner)
}

func signEthereumTypedData(seed []byte, typedDataRaw json.RawMessage) (*SignResult, error) {
	var td apitypes.TypedData
	if err := json.Unmarshal(typedDataRaw, &td); err != nil {
		return nil, fmt.Errorf("invalid typed_data: %w", err)
	}
	domainHash, err := td.HashStruct("EIP712Domain", td.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("eip712 domain hash failed: %w", err)
	}
	messageHash, err := td.HashStruct(td.PrimaryType, td.Message)
	if err != nil {
		return nil, fmt.Errorf("eip712 message hash failed: %w", err)
	}

	h := sha3.NewLegacyKeccak256()
	h.Write([]byte{0x19, 0x01})
	h.Write(domainHash[:])
	h.Write(messageHash[:])
	digest := h.Sum(nil)

	return signEthereum(seed, digest, "raw_hash")
}

func validatePersonalSignPayload(payload []byte) error {
	if !utf8.Valid(payload) {
		return errors.New("personal_sign guardrail: payload must be valid UTF-8 text")
	}
	if len(payload) == 0 {
		return errors.New("personal_sign guardrail: empty payload is not allowed")
	}

	text := string(payload)
	hasVisible := false
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return errors.New("personal_sign guardrail: payload contains non-printable characters")
		}
		if !unicode.IsSpace(r) {
			hasVisible = true
		}
	}
	if !hasVisible {
		return errors.New("personal_sign guardrail: payload must contain visible text")
	}

	trimmed := strings.TrimSpace(text)
	normalized := strings.TrimPrefix(strings.ToLower(trimmed), "0x")
	if len(normalized) >= 32 && len(normalized)%2 == 0 {
		allHex := true
		for _, r := range normalized {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				allHex = false
				break
			}
		}
		if allHex {
			return errors.New("personal_sign guardrail: hex-like payload is not allowed")
		}
	}
	return nil
}

func ValidateStrictPlainTextPayload(payload []byte, keywordBlacklist []string) error {
	if err := validatePersonalSignPayload(payload); err != nil {
		return err
	}

	if len(keywordBlacklist) == 0 {
		return nil
	}

	text := strings.ToLower(string(payload))
	for _, phrase := range keywordBlacklist {
		phrase = strings.ToLower(strings.TrimSpace(phrase))
		if phrase == "" {
			continue
		}
		if strings.Contains(text, phrase) {
			return fmt.Errorf("personal_sign guardrail: blocked keyword detected (%q)", phrase)
		}
	}
	return nil
}

func ValidateSuiPersonalSignMessage(payload []byte, keywordBlacklist []string) error {
	if err := validateSuiIntentPayload(payload, "personal_sign"); err != nil {
		return err
	}
	return ValidateStrictPlainTextPayload(payload[3:], keywordBlacklist)
}

func signEthereum(seed, payload []byte, mode string) (*SignResult, error) {
	priv, pub := btcec.PrivKeyFromBytes(seed)

	var hash []byte
	switch mode {
	case "personal_sign":
		if err := ValidateStrictPlainTextPayload(payload, nil); err != nil {
			return nil, err
		}

		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(payload))
		h := sha3.NewLegacyKeccak256()
		h.Write([]byte(prefix))
		h.Write(payload)
		hash = h.Sum(nil)
	case "raw_hash":
		hash = payload
	default:
		h := sha3.NewLegacyKeccak256()
		h.Write(payload)
		hash = h.Sum(nil)
	}

	// SignCompact returns [V (1) || R (32) || S (32)] where V is 27-34
	sig := ecdsa.SignCompact(priv, hash, false)

	// Reformat to Ethereum's [R || S || V] where V is 0 or 1
	// SignCompact V is at sig[0]. R is sig[1:33], S is sig[33:65].
	v := sig[0] - 27
	ethSig := make([]byte, 65)
	copy(ethSig[0:32], sig[1:33])
	copy(ethSig[32:64], sig[33:65])
	ethSig[64] = v

	return &SignResult{
		SignatureHex: "0x" + hex.EncodeToString(ethSig),
		From:         pubKeyToEthAddress(pub),
	}, nil
}

func pubKeyToEthAddress(pub *btcec.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 65 bytes: 0x04 || X || Y
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:]) // skip 0x04
	hash := h.Sum(nil)
	addr := hex.EncodeToString(hash[12:])
	return "0x" + addr // Simplified, ideally checksummed
}

func pubKeyToBitcoinAddress(pub *btcec.PublicKey) string {
	pubKeyHashInput := sha256.Sum256(pub.SerializeCompressed())
	ripemd := ripemd160.New()
	_, _ = ripemd.Write(pubKeyHashInput[:])
	pubKeyHash := ripemd.Sum(nil)

	payload := make([]byte, 0, 25)
	payload = append(payload, 0x00) // mainnet P2PKH
	payload = append(payload, pubKeyHash...)

	checksumInput := sha256.Sum256(payload)
	checksum := sha256.Sum256(checksumInput[:])
	payload = append(payload, checksum[:4]...)

	return base58.Encode(payload)
}

func pubKeyToTronAddress(pub *btcec.PublicKey) string {
	uncompressed := pub.SerializeUncompressed()
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(uncompressed[1:])
	sum := hash.Sum(nil)

	payload := make([]byte, 0, 25)
	payload = append(payload, 0x41)
	payload = append(payload, sum[len(sum)-20:]...)

	checksumInput := sha256.Sum256(payload)
	checksum := sha256.Sum256(checksumInput[:])
	payload = append(payload, checksum[:4]...)

	return base58.Encode(payload)
}

func signBitcoin(seed, tx []byte) (*SignResult, error) {
	priv, pub := btcec.PrivKeyFromBytes(seed)
	h := sha256.Sum256(tx)
	hash := sha256.Sum256(h[:])
	sig := ecdsa.Sign(priv, hash[:])
	return &SignResult{
		SignatureHex: hex.EncodeToString(sig.Serialize()),
		From:         pubKeyToBitcoinAddress(pub),
	}, nil
}

func signTronTransaction(seed, tx []byte) (*SignResult, error) {
	priv, pub := btcec.PrivKeyFromBytes(seed)
	hash := sha256.Sum256(tx)
	compact := ecdsa.SignCompact(priv, hash[:], false)
	if len(compact) != 65 {
		return nil, fmt.Errorf("unexpected tron signature length: %d", len(compact))
	}
	sig := make([]byte, 65)
	copy(sig[:64], compact[1:])
	sig[64] = compact[0]
	return &SignResult{
		SignatureHex: hex.EncodeToString(sig),
		From:         pubKeyToTronAddress(pub),
	}, nil
}

func signEd25519(seed, tx []byte) (*SignResult, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, tx)
	return &SignResult{SignatureHex: hex.EncodeToString(sig), From: hex.EncodeToString(pub)}, nil
}

func signSuiEd25519(seed, payload []byte) (*SignResult, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	digest := blake2b.Sum256(payload)
	sig := ed25519.Sign(priv, digest[:])
	return &SignResult{SignatureHex: hex.EncodeToString(sig), From: hex.EncodeToString(pub)}, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
