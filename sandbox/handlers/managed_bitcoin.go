package handlers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/pkg/bitcoinesplora"
)

const (
	defaultBitcoinFeeRateSatsVB = int64(8)
	bitcoinDustThresholdSats    = int64(546)
)

var bitcoinHTTPClient = &http.Client{Timeout: 20 * time.Second}

type bitcoinUTXO struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"`
	Status struct {
		Confirmed bool `json:"confirmed"`
	} `json:"status"`
}

type bitcoinUTXOPlan struct {
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value int64  `json:"value_sats"`
}

func executeManagedBitcoinTransfer(s *signer.Signer, req *TransferRequest, from string, intent *policy.Intent) (*TransferResponse, error) {
	if strings.TrimSpace(req.TokenContract) != "" {
		return nil, errors.New("bitcoin transfer does not support token_contract")
	}
	amountSats, ok := new(big.Int).SetString(strings.TrimSpace(req.AmountWei), 10)
	if !ok || amountSats.Sign() <= 0 {
		return nil, errors.New("amount_wei must be a positive integer string")
	}
	if !amountSats.IsInt64() {
		return nil, errors.New("bitcoin amount exceeds int64 satoshi range")
	}

	signReq := signer.SignRequest{
		Chain:           "bitcoin",
		SignMode:        "transaction",
		UID:             req.UID,
		To:              req.To,
		AmountWei:       req.AmountWei,
		BuilderKind:     "native_transfer",
		ConfirmedByUser: true,
		IsUserApproval:  true,
		ApprovalID:      strings.TrimSpace(req.ApprovalID),
		ExecutionToken:  strings.TrimSpace(req.ExecutionToken),
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, err
	}
	seed, err := s.ReconstructSeed(&signReq)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(seed)

	utxos, err := fetchBitcoinUTXOs(from)
	if err != nil {
		return nil, fmt.Errorf("failed to load bitcoin utxos: %w", err)
	}
	if len(utxos) == 0 {
		return nil, errors.New("wallet does not have any bitcoin utxos")
	}

	feeRate, err := fetchBitcoinFeeRateSatsPerVB()
	if err != nil {
		feeRate = defaultBitcoinFeeRateSatsVB
	}
	tx, selected, feeSats, changeSats, err := buildBitcoinTransferTx(from, req.To, amountSats.Int64(), feeRate, utxos)
	if err != nil {
		return nil, err
	}
	_ = selected
	_ = feeSats
	_ = changeSats

	senderAddr, err := btcutil.DecodeAddress(from, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("invalid bitcoin sender address: %w", err)
	}
	senderScript, err := txscript.PayToAddrScript(senderAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to derive bitcoin sender script: %w", err)
	}
	if err := signBitcoinTransactionInputs(tx, senderScript, seed); err != nil {
		return nil, err
	}

	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		return nil, fmt.Errorf("failed to serialize bitcoin transaction: %w", err)
	}
	rawTxHex := "0x" + hex.EncodeToString(raw.Bytes())
	broadcastTxID, err := broadcastBitcoinRawTx(hex.EncodeToString(raw.Bytes()))
	if err != nil {
		return nil, err
	}
	refreshBroadcastChainAssets("bitcoin")
	policyEngine.Commit(intent)

	return &TransferResponse{
		Chain:       "bitcoin",
		From:        from,
		To:          req.To,
		AmountWei:   amountSats.String(),
		SubmittedID: broadcastTxID,
		TxHash:      broadcastTxID,
		RawTxHex:    rawTxHex,
	}, nil
}

func fetchBitcoinUTXOs(address string) ([]bitcoinUTXO, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("missing bitcoin address")
	}
	path := "/address/" + url.PathEscape(address) + "/utxo"
	var utxos []bitcoinUTXO
	if err := bitcoinesplora.FetchGET(bitcoinHTTPClient, path, &utxos); err != nil {
		return nil, err
	}
	sort.SliceStable(utxos, func(i, j int) bool {
		if utxos[i].Status.Confirmed != utxos[j].Status.Confirmed {
			return utxos[i].Status.Confirmed
		}
		if utxos[i].Value == utxos[j].Value {
			return utxos[i].TxID < utxos[j].TxID
		}
		return utxos[i].Value > utxos[j].Value
	})
	return utxos, nil
}

func fetchBitcoinFeeRateSatsPerVB() (int64, error) {
	override := strings.TrimSpace(os.Getenv("BITCOIN_FEE_RATE_SATS_PER_VBYTE"))
	if override != "" {
		rate, err := strconv.ParseInt(override, 10, 64)
		if err != nil || rate <= 0 {
			return 0, fmt.Errorf("invalid BITCOIN_FEE_RATE_SATS_PER_VBYTE")
		}
		return rate, nil
	}

	return bitcoinesplora.PickRecommendedFeeSatsPerVB(bitcoinHTTPClient)
}

func buildBitcoinTransferTx(from, to string, amountSats, feeRate int64, utxos []bitcoinUTXO) (*wire.MsgTx, []bitcoinUTXO, int64, int64, error) {
	if amountSats <= 0 {
		return nil, nil, 0, 0, errors.New("amount must be positive")
	}
	if feeRate <= 0 {
		feeRate = defaultBitcoinFeeRateSatsVB
	}

	senderAddr, err := btcutil.DecodeAddress(from, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("invalid bitcoin sender address: %w", err)
	}
	if _, ok := senderAddr.(*btcutil.AddressPubKeyHash); !ok {
		return nil, nil, 0, 0, errors.New("bitcoin sender address must be legacy P2PKH")
	}
	recipientAddr, err := btcutil.DecodeAddress(to, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("invalid bitcoin recipient address: %w", err)
	}
	if !recipientAddr.IsForNet(&chaincfg.MainNetParams) {
		return nil, nil, 0, 0, errors.New("bitcoin recipient must be a mainnet address")
	}

	selected := make([]bitcoinUTXO, 0, len(utxos))
	total := int64(0)
	for _, utxo := range utxos {
		if utxo.Value <= 0 {
			continue
		}
		selected = append(selected, utxo)
		total += utxo.Value
		fee := estimateBitcoinFee(len(selected), 2, feeRate)
		if total < amountSats+fee {
			continue
		}

		change := total - amountSats - fee
		if change > 0 && change < bitcoinDustThresholdSats {
			change = 0
			fee = total - amountSats
		}

		tx, err := constructBitcoinTx(from, to, amountSats, selected, change)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		return tx, selected, fee, change, nil
	}

	return nil, nil, 0, 0, errors.New("insufficient bitcoin balance")
}

func constructBitcoinTx(from, to string, amountSats int64, selected []bitcoinUTXO, changeSats int64) (*wire.MsgTx, error) {
	senderAddr, err := btcutil.DecodeAddress(from, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	recipientAddr, err := btcutil.DecodeAddress(to, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	changeAddr := senderAddr
	senderScript, err := txscript.PayToAddrScript(senderAddr)
	if err != nil {
		return nil, err
	}
	recipientScript, err := txscript.PayToAddrScript(recipientAddr)
	if err != nil {
		return nil, err
	}
	changeScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(2)
	for _, utxo := range selected {
		hash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("invalid bitcoin utxo txid %q: %w", utxo.TxID, err)
		}
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: utxo.Vout,
			},
			Sequence: wire.MaxTxInSequenceNum,
		})
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    amountSats,
		PkScript: recipientScript,
	})
	if changeSats > 0 {
		tx.AddTxOut(&wire.TxOut{
			Value:    changeSats,
			PkScript: changeScript,
		})
	}

	_ = senderScript
	return tx, nil
}

func signBitcoinTransactionInputs(tx *wire.MsgTx, senderScript []byte, seed []byte) error {
	if tx == nil {
		return errors.New("missing bitcoin transaction")
	}
	priv, _ := btcec.PrivKeyFromBytes(seed)
	for i := range tx.TxIn {
		sigScript, err := txscript.SignatureScript(tx, i, senderScript, txscript.SigHashAll, priv, true)
		if err != nil {
			return fmt.Errorf("failed to sign bitcoin input %d: %w", i, err)
		}
		tx.TxIn[i].SignatureScript = sigScript
	}
	return nil
}

func broadcastBitcoinRawTx(rawTxHex string) (string, error) {
	rawTxHex = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rawTxHex, "0x"), "0X"))
	if rawTxHex == "" {
		return "", errors.New("missing bitcoin raw transaction hex")
	}
	rawBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", fmt.Errorf("invalid bitcoin raw transaction hex: %w", err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawBytes)); err != nil {
		return "", fmt.Errorf("invalid bitcoin raw transaction: %w", err)
	}
	localTxID := tx.TxID()

	body, err := bitcoinesplora.PostText(bitcoinHTTPClient, "/tx", "text/plain", rawTxHex)
	if err != nil {
		return "", err
	}
	txid := strings.TrimSpace(string(body))
	if txid == "" {
		txid = localTxID
	}
	return txid, nil
}

func estimateBitcoinFee(inputCount, outputCount int, feeRate int64) int64 {
	size := int64(10 + inputCount*148 + outputCount*34)
	return size * feeRate
}

func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
