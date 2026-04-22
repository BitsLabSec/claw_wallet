package handlers

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	gethcommon "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	gc "sandbox/internals/crypto"
	"sandbox/internals/signer"
)

const (
	defaultZeroGNetwork        = "testnet"
	testnetZeroGStorageRPC     = "https://evmrpc-testnet.0g.ai"
	testnetZeroGStorageIndexer = "https://indexer-storage-testnet-turbo.0g.ai"
	testnetZeroGVaultAddress   = "0x254bfe1433C4C10d05cD37B6eF3F062323FC6be5"
	mainnetZeroGStorageRPC     = "https://evmrpc.0g.ai"
	mainnetZeroGStorageIndexer = "https://indexer-storage-turbo.0g.ai"
	mainnetZeroGVaultAddress   = "0xa8DF92c6724Db748B82d90f50b4b1e1542175440"
)

const recoveryVaultABIJSON = `[
  {
    "inputs": [
      {"internalType":"bytes32","name":"uidHash","type":"bytes32"},
      {"internalType":"bytes32","name":"share2Receipt","type":"bytes32"},
      {"internalType":"bytes32","name":"share2Root","type":"bytes32"},
      {"internalType":"bytes32","name":"share2Commitment","type":"bytes32"},
      {"internalType":"bytes32","name":"share3Receipt","type":"bytes32"},
      {"internalType":"bytes32","name":"share3Root","type":"bytes32"},
      {"internalType":"bytes32","name":"share3Commitment","type":"bytes32"},
      {"internalType":"uint64","name":"epoch","type":"uint64"}
    ],
    "name":"registerBackup",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  }
]`

type zeroGBackupRequest struct {
	RPCURL       string `json:"rpc_url,omitempty"`
	IndexerURL   string `json:"indexer_url,omitempty"`
	VaultAddress string `json:"vault_address,omitempty"`
}

type zeroGStorageConfig struct {
	RPCURL     string
	IndexerURL string
}

type recoveryVaultConfig struct {
	RPCURL       string
	VaultAddress string
}

type zeroGNetworkConfig struct {
	Storage      zeroGStorageConfig
	VaultAddress string
}

type zeroGBackupArtifact struct {
	Kind          string
	Ciphertext    []byte
	Nonce         []byte
	UploadBytes   []byte
	CommitmentHex string
}

type zeroGRecoveryArtifacts struct {
	UID          string
	UIDHashHex   string
	MasterPubKey string
	Epoch        uint64
	SourceShare2 signer.EncryptedShare
	SourceShare3 signer.EncryptedShare
	SEK          []byte
	Share2       zeroGBackupArtifact
	Share3       zeroGBackupArtifact
}

type zeroGUploadResult struct {
	RootHash string
	TxHash   string
}

type zeroGBackupRegistration struct {
	UIDHashHex          string
	Epoch               uint64
	Share2ReceiptHex    string
	Share2RootHash      string
	Share2CommitmentHex string
	Share3ReceiptHex    string
	Share3RootHash      string
	Share3CommitmentHex string
}

type zeroGBackupShareResponse struct {
	ReceiptHex    string `json:"receipt_hex"`
	RootHash      string `json:"root_hash"`
	TxHash        string `json:"tx_hash"`
	CommitmentHex string `json:"commitment_hex"`
}

type zeroGBackupResponse struct {
	UIDHashHex   string                   `json:"uid_hash_hex"`
	Epoch        uint64                   `json:"epoch"`
	VaultAddress string                   `json:"vault_address"`
	VaultTxHash  string                   `json:"vault_tx_hash"`
	Share2       zeroGBackupShareResponse `json:"share2"`
	Share3       zeroGBackupShareResponse `json:"share3"`
}

type zeroGBackupUploader interface {
	Upload(kind string, blob []byte) (zeroGUploadResult, error)
}

type zeroGBackupUploaderFunc func(kind string, blob []byte) (zeroGUploadResult, error)

func (f zeroGBackupUploaderFunc) Upload(kind string, blob []byte) (zeroGUploadResult, error) {
	return f(kind, blob)
}

type recoveryVaultRegistrar interface {
	Register(req zeroGBackupRegistration) (string, error)
}

type recoveryVaultRegistrarFunc func(req zeroGBackupRegistration) (string, error)

func (f recoveryVaultRegistrarFunc) Register(req zeroGBackupRegistration) (string, error) {
	return f(req)
}

var newZeroGBackupUploader = func(cfg zeroGStorageConfig, evmPrivateKeyHex string) (zeroGBackupUploader, error) {
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return nil, errors.New("0g storage rpc url is required")
	}
	if strings.TrimSpace(cfg.IndexerURL) == "" {
		return nil, errors.New("0g storage indexer url is required")
	}
	if strings.TrimSpace(evmPrivateKeyHex) == "" {
		return nil, errors.New("evm private key is required")
	}
	return &realZeroGBackupUploader{
		rpcURL:        strings.TrimSpace(cfg.RPCURL),
		indexerURL:    strings.TrimSpace(cfg.IndexerURL),
		privateKeyHex: strings.TrimSpace(evmPrivateKeyHex),
	}, nil
}

var newRecoveryVaultRegistrar = func(cfg recoveryVaultConfig, evmPrivateKeyHex string) (recoveryVaultRegistrar, error) {
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return nil, errors.New("0g recovery vault rpc url is required")
	}
	if strings.TrimSpace(cfg.VaultAddress) == "" {
		return nil, errors.New("0g recovery vault address is required")
	}
	if strings.TrimSpace(evmPrivateKeyHex) == "" {
		return nil, errors.New("evm private key is required")
	}
	return &realRecoveryVaultRegistrar{
		rpcURL:        strings.TrimSpace(cfg.RPCURL),
		vaultAddress:  strings.TrimSpace(cfg.VaultAddress),
		privateKeyHex: strings.TrimSpace(evmPrivateKeyHex),
	}, nil
}

type realZeroGBackupUploader struct {
	rpcURL        string
	indexerURL    string
	privateKeyHex string
}

func (u *realZeroGBackupUploader) Upload(kind string, blob []byte) (zeroGUploadResult, error) {
	data, err := core.NewDataInMemory(blob)
	if err != nil {
		return zeroGUploadResult{}, err
	}
	w3Client := blockchain.MustNewWeb3(u.rpcURL, u.privateKeyHex)
	defer w3Client.Close()

	indexerClient, err := indexer.NewClient(u.indexerURL, indexer.IndexerClientOption{})
	if err != nil {
		return zeroGUploadResult{}, err
	}
	txHashes, roots, err := indexerClient.SplitableUpload(context.Background(), w3Client, data, transfer.UploadOption{
		FinalityRequired: transfer.TransactionPacked,
		Method:           "min",
		FullTrusted:      true,
	})
	if err != nil {
		return zeroGUploadResult{}, fmt.Errorf("0g upload %s failed: %w", kind, err)
	}
	if len(roots) == 0 {
		return zeroGUploadResult{}, fmt.Errorf("0g upload %s returned no root", kind)
	}
	txHash := ""
	if len(txHashes) > 0 {
		txHash = txHashes[0].Hex()
	}
	return zeroGUploadResult{
		RootHash: roots[0].Hex(),
		TxHash:   txHash,
	}, nil
}

type realRecoveryVaultRegistrar struct {
	rpcURL        string
	vaultAddress  string
	privateKeyHex string
}

func (r *realRecoveryVaultRegistrar) Register(req zeroGBackupRegistration) (string, error) {
	client, err := ethclient.Dial(r.rpcURL)
	if err != nil {
		return "", err
	}
	defer client.Close()

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return "", err
	}
	privateKey, err := gethcrypto.HexToECDSA(strings.TrimPrefix(r.privateKeyHex, "0x"))
	if err != nil {
		return "", err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return "", err
	}
	parsedABI, err := abi.JSON(strings.NewReader(recoveryVaultABIJSON))
	if err != nil {
		return "", err
	}
	contract := bind.NewBoundContract(gethcommon.HexToAddress(r.vaultAddress), parsedABI, client, client, client)
	tx, err := contract.Transact(
		auth,
		"registerBackup",
		gethcommon.HexToHash(req.UIDHashHex),
		gethcommon.HexToHash(req.Share2ReceiptHex),
		gethcommon.HexToHash(req.Share2RootHash),
		gethcommon.HexToHash(req.Share2CommitmentHex),
		gethcommon.HexToHash(req.Share3ReceiptHex),
		gethcommon.HexToHash(req.Share3RootHash),
		gethcommon.HexToHash(req.Share3CommitmentHex),
		req.Epoch,
	)
	if err != nil {
		return "", err
	}
	return tx.Hash().Hex(), nil
}

func handleZeroGRecoveryBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req zeroGBackupRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid json body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	resp, err := performZeroGRecoveryBackup(time.Now().UTC(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if isZeroGBackupStateError(err) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func performZeroGRecoveryBackup(now time.Time, req zeroGBackupRequest) (*zeroGBackupResponse, error) {
	mu.RLock()
	artifacts, err := buildZeroGRecoveryArtifactsLocked(now)
	mu.RUnlock()
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(artifacts.SEK)

	privateKeyHex, err := deriveZeroGEVMPrivateKeyHex(
		artifacts.MasterPubKey,
		artifacts.SourceShare2,
		artifacts.SourceShare3,
		artifacts.SEK,
	)
	if err != nil {
		return nil, err
	}

	defaults := zeroGBackupDefaults()
	storageCfg := zeroGStorageConfig{
		RPCURL:     firstNonEmpty(req.RPCURL, env("CLAY_0G_STORAGE_RPC", defaults.Storage.RPCURL)),
		IndexerURL: firstNonEmpty(req.IndexerURL, env("CLAY_0G_STORAGE_INDEXER", defaults.Storage.IndexerURL)),
	}
	uploader, err := newZeroGBackupUploader(storageCfg, privateKeyHex)
	if err != nil {
		return nil, err
	}
	share2Upload, err := uploader.Upload("share2", artifacts.Share2.UploadBytes)
	if err != nil {
		return nil, err
	}
	share3Upload, err := uploader.Upload("share3", artifacts.Share3.UploadBytes)
	if err != nil {
		return nil, err
	}

	share2Receipt := gethcrypto.Keccak256Hash(
		gethcommon.HexToHash(artifacts.UIDHashHex).Bytes(),
		[]byte("share2"),
		gethcommon.HexToHash(share2Upload.RootHash).Bytes(),
		gethcommon.HexToHash(artifacts.Share2.CommitmentHex).Bytes(),
	).Hex()
	share3Receipt := gethcrypto.Keccak256Hash(
		gethcommon.HexToHash(artifacts.UIDHashHex).Bytes(),
		[]byte("share3"),
		gethcommon.HexToHash(share3Upload.RootHash).Bytes(),
		gethcommon.HexToHash(artifacts.Share3.CommitmentHex).Bytes(),
	).Hex()

	registration := zeroGBackupRegistration{
		UIDHashHex:          artifacts.UIDHashHex,
		Epoch:               artifacts.Epoch,
		Share2ReceiptHex:    share2Receipt,
		Share2RootHash:      share2Upload.RootHash,
		Share2CommitmentHex: artifacts.Share2.CommitmentHex,
		Share3ReceiptHex:    share3Receipt,
		Share3RootHash:      share3Upload.RootHash,
		Share3CommitmentHex: artifacts.Share3.CommitmentHex,
	}

	vaultAddress := firstNonEmpty(req.VaultAddress, env("CLAY_0G_RECOVERY_VAULT_ADDRESS", defaults.VaultAddress))
	registrar, err := newRecoveryVaultRegistrar(recoveryVaultConfig{
		RPCURL:       storageCfg.RPCURL,
		VaultAddress: vaultAddress,
	}, privateKeyHex)
	if err != nil {
		return nil, err
	}
	vaultTxHash, err := registrar.Register(registration)
	if err != nil {
		return nil, err
	}

	return &zeroGBackupResponse{
		UIDHashHex:   artifacts.UIDHashHex,
		Epoch:        artifacts.Epoch,
		VaultAddress: vaultAddress,
		VaultTxHash:  vaultTxHash,
		Share2: zeroGBackupShareResponse{
			ReceiptHex:    share2Receipt,
			RootHash:      share2Upload.RootHash,
			TxHash:        share2Upload.TxHash,
			CommitmentHex: artifacts.Share2.CommitmentHex,
		},
		Share3: zeroGBackupShareResponse{
			ReceiptHex:    share3Receipt,
			RootHash:      share3Upload.RootHash,
			TxHash:        share3Upload.TxHash,
			CommitmentHex: artifacts.Share3.CommitmentHex,
		},
	}, nil
}

func zeroGBackupDefaults() zeroGNetworkConfig {
	switch strings.ToLower(strings.TrimSpace(env("CLAY_0G_NETWORK", defaultZeroGNetwork))) {
	case "mainnet":
		return zeroGNetworkConfig{
			Storage: zeroGStorageConfig{
				RPCURL:     mainnetZeroGStorageRPC,
				IndexerURL: mainnetZeroGStorageIndexer,
			},
			VaultAddress: mainnetZeroGVaultAddress,
		}
	default:
		return zeroGNetworkConfig{
			Storage: zeroGStorageConfig{
				RPCURL:     testnetZeroGStorageRPC,
				IndexerURL: testnetZeroGStorageIndexer,
			},
			VaultAddress: testnetZeroGVaultAddress,
		}
	}
}

func buildZeroGRecoveryArtifactsLocked(now time.Time) (*zeroGRecoveryArtifacts, error) {
	if strings.TrimSpace(boundUid) == "" {
		return nil, errors.New("uid is unavailable for 0g backup")
	}
	if strings.TrimSpace(masterPubKey) == "" {
		return nil, errors.New("master public key is unavailable for 0g backup")
	}
	if localShare2.Cipher == "" {
		return nil, errors.New("local share2 is unavailable for 0g backup")
	}
	if encShare3.Cipher == "" {
		return nil, errors.New("local share3 is unavailable for 0g backup")
	}
	if len(sekKey) == 0 {
		return nil, errors.New("sek is unavailable for 0g backup")
	}

	currentUID := strings.TrimSpace(boundUid)
	currentMasterPubKey := strings.TrimSpace(masterPubKey)
	currentShare2 := localShare2
	currentShare3 := encShare3
	currentSEK := append([]byte(nil), sekKey...)
	epoch := uint64(now.Unix())
	uidHash := gethcrypto.Keccak256Hash([]byte(currentUID)).Hex()
	share2Artifact, err := buildZeroGBackupArtifact("share2", currentUID, currentMasterPubKey, currentShare2, currentSEK)
	if err != nil {
		zeroizeBytes(currentSEK)
		return nil, err
	}
	share3Artifact, err := buildZeroGBackupArtifact("share3", currentUID, currentMasterPubKey, currentShare3, currentSEK)
	if err != nil {
		zeroizeBytes(currentSEK)
		return nil, err
	}

	return &zeroGRecoveryArtifacts{
		UID:          currentUID,
		UIDHashHex:   uidHash,
		MasterPubKey: currentMasterPubKey,
		Epoch:        epoch,
		SourceShare2: currentShare2,
		SourceShare3: currentShare3,
		SEK:          currentSEK,
		Share2:       share2Artifact,
		Share3:       share3Artifact,
	}, nil
}

func buildZeroGBackupArtifact(kind, uid, masterPubKey string, share signer.EncryptedShare, sek []byte) (zeroGBackupArtifact, error) {
	plain, err := json.Marshal(map[string]any{
		"uid":             uid,
		"master_pub_key":  masterPubKey,
		"kind":            kind,
		"encrypted_share": share,
	})
	if err != nil {
		return zeroGBackupArtifact{}, err
	}
	ciphertext, nonce, err := gc.EncryptData(sek, plain)
	if err != nil {
		return zeroGBackupArtifact{}, err
	}
	uploadBytes, err := json.Marshal(map[string]any{
		"version":        1,
		"uid":            uid,
		"master_pub_key": masterPubKey,
		"kind":           kind,
		"ciphertext_hex": hex.EncodeToString(ciphertext),
		"nonce_hex":      hex.EncodeToString(nonce),
	})
	if err != nil {
		return zeroGBackupArtifact{}, err
	}
	return zeroGBackupArtifact{
		Kind:          kind,
		Ciphertext:    ciphertext,
		Nonce:         nonce,
		UploadBytes:   uploadBytes,
		CommitmentHex: gethcrypto.Keccak256Hash(uploadBytes).Hex(),
	}, nil
}

func deriveZeroGEVMPrivateKeyHex(currentMasterPubKey string, share2, share3 signer.EncryptedShare, sek []byte) (string, error) {
	if strings.TrimSpace(currentMasterPubKey) == "" {
		return "", errors.New("master public key is unavailable for 0g backup")
	}
	if share2.Cipher == "" || share3.Cipher == "" {
		return "", errors.New("recovery shares are unavailable for 0g backup")
	}
	if len(sek) == 0 {
		return "", errors.New("sek is unavailable for 0g backup")
	}

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	sharePIN := hex.EncodeToString(sek)
	tempSigner, err := signer.New(share3, sharePIN, priv, currentMasterPubKey)
	if err != nil {
		return "", err
	}
	defer tempSigner.Wipe()

	seed, err := tempSigner.ReconstructSeed(&signer.SignRequest{EncShare1: share2})
	if err != nil {
		return "", err
	}
	defer zeroizeBytes(seed)

	evmSeed, err := signer.DeriveSecp256k1(seed, "m/44'/60'/0'/0/0")
	if err != nil {
		return "", err
	}
	defer zeroizeBytes(evmSeed)

	return hex.EncodeToString(evmSeed), nil
}

func isZeroGBackupStateError(err error) bool {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "uid is unavailable") ||
		strings.Contains(msg, "master public key is unavailable") ||
		strings.Contains(msg, "local share2 is unavailable") ||
		strings.Contains(msg, "local share3 is unavailable") ||
		strings.Contains(msg, "recovery shares are unavailable") ||
		strings.Contains(msg, "sek is unavailable")
}
