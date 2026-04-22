package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sandbox/internals/assets"
	"sandbox/internals/audit"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
)

type BroadcastRequest struct {
	Chain         string          `json:"chain"`
	UID           string          `json:"uid,omitempty"`
	RawTxHex      string          `json:"raw_tx_hex,omitempty"`
	RawTxBase64   string          `json:"raw_tx_base64,omitempty"`
	TxBytesHex    string          `json:"tx_bytes_hex,omitempty"`
	TxBytesBase64 string          `json:"tx_bytes_base64,omitempty"`
	Signature     string          `json:"signature,omitempty"`
	Signatures    []string        `json:"signatures,omitempty"`
	Options       json.RawMessage `json:"options,omitempty"`
}

type BroadcastResponse struct {
	Chain       string `json:"chain"`
	SubmittedID string `json:"submitted_id"`
	TxHash      string `json:"tx_hash,omitempty"`
	Signature   string `json:"signature,omitempty"`
	Digest      string `json:"digest,omitempty"`
}

// 通用交易广播
func handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := BroadcastSignedTransaction(&req)
	if err != nil {
		audit.LogEvent("tx_broadcast", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.LogEvent("tx_broadcast", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s id=%s", res.Chain, res.SubmittedID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// 发送交易--调用rpc接口，支持不同链的交易发送逻辑
func BroadcastSignedTransaction(req *BroadcastRequest) (*BroadcastResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("missing request")
	}

	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		return nil, fmt.Errorf("chain is required")
	}
	if !isPublicChainEnabled(chain) {
		return nil, errors.New(publicChainDisabledMessage(chain))
	}

	switch {
	case signer.IsEVMChain(chain):
		rawTxHex, err := ResolveHexOrBase64Payload(req.RawTxHex, req.RawTxBase64)
		if err != nil {
			return nil, err
		}

		var txHash string
		if err := callChainRPC(chain, "eth_sendRawTransaction", []interface{}{rawTxHex}, &txHash); err != nil {
			return nil, err
		}
		refreshBroadcastChainAssets(chain)
		return &BroadcastResponse{
			Chain:       chain,
			SubmittedID: txHash,
			TxHash:      txHash,
		}, nil
	case chain == "solana":
		rawTxBase64, err := ResolveBase64OrHexPayload(req.RawTxBase64, req.RawTxHex)
		if err != nil {
			return nil, err
		}

		params := []interface{}{
			rawTxBase64,
			map[string]interface{}{
				"encoding":            "base64",
				"preflightCommitment": "confirmed",
			},
		}
		var signature string
		if err := callChainRPC(chain, "sendTransaction", params, &signature); err != nil {
			return nil, err
		}
		refreshBroadcastChainAssets(chain)
		return &BroadcastResponse{
			Chain:       chain,
			SubmittedID: signature,
			Signature:   signature,
		}, nil
	case chain == "sui":
		txBytesBase64, err := ResolveBase64OrHexPayload(req.TxBytesBase64, req.TxBytesHex)
		if err != nil {
			return nil, err
		}
		signatures := normalizedSignatures(req.Signature, req.Signatures)
		if len(signatures) == 0 {
			return nil, fmt.Errorf("sui broadcast requires signature or signatures")
		}

		options := map[string]bool{
			"showEffects": true,
		}
		if len(req.Options) > 0 {
			if err := json.Unmarshal(req.Options, &options); err != nil {
				return nil, fmt.Errorf("invalid options payload: %w", err)
			}
		}

		var result struct {
			Digest string `json:"digest"`
		}
		params := []interface{}{txBytesBase64, signatures, options, "WaitForLocalExecution"}
		if err := callChainRPC(chain, "sui_executeTransactionBlock", params, &result); err != nil {
			return nil, err
		}
		if strings.TrimSpace(result.Digest) == "" {
			return nil, fmt.Errorf("sui broadcast returned empty digest")
		}
		refreshBroadcastChainAssets(chain)
		return &BroadcastResponse{
			Chain:       chain,
			SubmittedID: result.Digest,
			Digest:      result.Digest,
		}, nil
	case chain == "bitcoin":
		rawTxHex, err := ResolveHexOrBase64Payload(req.RawTxHex, req.RawTxBase64)
		if err != nil {
			return nil, err
		}
		txid, err := broadcastBitcoinRawTx(rawTxHex)
		if err != nil {
			return nil, err
		}
		refreshBroadcastChainAssets(chain)
		return &BroadcastResponse{
			Chain:       chain,
			SubmittedID: txid,
			TxHash:      txid,
		}, nil
	case chain == "tron":
		payloadHex, err := ResolveHexOrBase64Payload(req.RawTxHex, req.RawTxBase64)
		if err != nil {
			return nil, err
		}
		signatures := normalizedSignatures(req.Signature, req.Signatures)
		signedTxHex := ""
		txID := ""
		if len(signatures) > 0 {
			signedTxHex, txID, err = tronSignedTransactionHex(payloadHex, signatures)
			if err != nil {
				return nil, err
			}
		} else {
			signedTxHex = strings.TrimPrefix(strings.TrimSpace(payloadHex), "0x")
			signedTxBytes, err := DecodeHex(payloadHex)
			if err != nil {
				return nil, fmt.Errorf("invalid tron signed transaction hex: %w", err)
			}
			rawDataBytes, err := tronRawDataFromSignedTransaction(signedTxBytes)
			if err != nil {
				return nil, err
			}
			txID = tronTransactionID(rawDataBytes)
		}

		rpcURL, err := chainRPCURL("tron")
		if err != nil {
			return nil, err
		}
		rpcURL = strings.TrimRight(strings.TrimSpace(rpcURL), "/")
		var tronRes struct {
			Result  bool   `json:"result"`
			TxID    string `json:"txid"`
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if err := postJSON(rpcURL+"/wallet/broadcasthex", map[string]any{
			"transaction": signedTxHex,
			"visible":     true,
		}, &tronRes); err != nil {
			return nil, err
		}
		if !tronRes.Result {
			reason := strings.TrimSpace(tronRes.Message)
			if reason == "" {
				reason = strings.TrimSpace(tronRes.Code)
			}
			if reason == "" {
				reason = "tron broadcast failed"
			}
			return nil, errors.New(reason)
		}
		if strings.TrimSpace(tronRes.TxID) != "" {
			txID = strings.TrimSpace(tronRes.TxID)
		}
		refreshBroadcastChainAssets(chain)
		return &BroadcastResponse{
			Chain:       chain,
			SubmittedID: txID,
			TxHash:      txID,
		}, nil
	default:
		return nil, fmt.Errorf("broadcast is not implemented for chain %q", chain)
	}
}

func refreshBroadcastChainAssets(chain string) {
	snapshot := SnapshotAddresses()
	from, err := utils.TransferFromAddress(strings.ToLower(strings.TrimSpace(chain)), snapshot)
	if err != nil || strings.TrimSpace(from) == "" {
		return
	}
	assets.RefreshOne(strings.ToLower(strings.TrimSpace(chain)), from)
}

func ResolveHexOrBase64Payload(rawHex, rawBase64 string) (string, error) {
	if strings.TrimSpace(rawHex) != "" {
		if _, err := DecodeHex(rawHex); err != nil {
			return "", fmt.Errorf("invalid raw_tx_hex: %w", err)
		}
		if strings.HasPrefix(rawHex, "0x") || strings.HasPrefix(rawHex, "0X") {
			return "0x" + strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(rawHex), "0x"), "0X"), nil
		}
		return "0x" + strings.TrimSpace(rawHex), nil
	}
	if strings.TrimSpace(rawBase64) == "" {
		return "", fmt.Errorf("raw signed transaction payload is required")
	}
	payload, err := decodeBase64Payload(rawBase64)
	if err != nil {
		return "", fmt.Errorf("invalid raw_tx_base64: %w", err)
	}
	return "0x" + hex.EncodeToString(payload), nil
}

func ResolveBase64OrHexPayload(rawBase64, rawHex string) (string, error) {
	if strings.TrimSpace(rawBase64) != "" {
		if _, err := decodeBase64Payload(rawBase64); err != nil {
			return "", fmt.Errorf("invalid base64 payload: %w", err)
		}
		return strings.TrimSpace(rawBase64), nil
	}
	if strings.TrimSpace(rawHex) == "" {
		return "", fmt.Errorf("signed payload is required")
	}
	payload, err := DecodeHex(rawHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func decodeBase64Payload(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty payload")
	}
	payload, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		return payload, nil
	}
	payload, rawErr := base64.RawStdEncoding.DecodeString(raw)
	if rawErr == nil {
		return payload, nil
	}
	return nil, err
}

func normalizedSignatures(signature string, signatures []string) []string {
	var result []string
	if strings.TrimSpace(signature) != "" {
		result = append(result, strings.TrimSpace(signature))
	}
	for _, item := range signatures {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func tronTransactionID(rawDataBytes []byte) string {
	txID := sha256.Sum256(rawDataBytes)
	return hex.EncodeToString(txID[:])
}

func tronSignedTransactionHex(rawDataHex string, signatures []string) (string, string, error) {
	rawDataBytes, err := DecodeHex(rawDataHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid tron raw_data_hex: %w", err)
	}
	if len(rawDataBytes) == 0 {
		return "", "", fmt.Errorf("tron raw_data_hex is empty")
	}

	signed := make([]byte, 0, len(rawDataBytes)+96)
	signed = append(signed, encodeTronBytesField(1, rawDataBytes)...)
	for _, sig := range signatures {
		sigBytes, err := DecodeHex(sig)
		if err != nil {
			return "", "", fmt.Errorf("invalid tron signature hex: %w", err)
		}
		if len(sigBytes) != 65 {
			return "", "", fmt.Errorf("tron signature must be 65 bytes, got %d", len(sigBytes))
		}
		signed = append(signed, encodeTronBytesField(2, sigBytes)...)
	}

	return hex.EncodeToString(signed), tronTransactionID(rawDataBytes), nil
}

func tronRawDataFromSignedTransaction(txBytes []byte) ([]byte, error) {
	if len(txBytes) == 0 {
		return nil, fmt.Errorf("tron signed transaction is empty")
	}
	tag, n := decodeVarint(txBytes)
	if n <= 0 {
		return nil, fmt.Errorf("invalid tron signed transaction")
	}
	if tag != 0x0a {
		return nil, fmt.Errorf("tron signed transaction missing raw_data field")
	}
	length, m := decodeVarint(txBytes[n:])
	if m <= 0 {
		return nil, fmt.Errorf("invalid tron raw_data length")
	}
	start := n + m
	end := start + int(length)
	if end > len(txBytes) {
		return nil, fmt.Errorf("tron raw_data length exceeds payload size")
	}
	return append([]byte(nil), txBytes[start:end]...), nil
}

func encodeTronBytesField(fieldNum int, value []byte) []byte {
	if fieldNum <= 0 {
		return nil
	}
	tag := uint64(fieldNum<<3 | 2)
	out := make([]byte, 0, 1+len(value)+10)
	out = append(out, encodeVarint(tag)...)
	out = append(out, encodeVarint(uint64(len(value)))...)
	out = append(out, value...)
	return out
}

func encodeVarint(value uint64) []byte {
	var buf [10]byte
	n := 0
	for value >= 0x80 {
		buf[n] = byte(value) | 0x80
		value >>= 7
		n++
	}
	buf[n] = byte(value)
	return append([]byte(nil), buf[:n+1]...)
}

func decodeVarint(data []byte) (uint64, int) {
	var value uint64
	for i, b := range data {
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, i + 1
		}
		if i >= 9 {
			break
		}
	}
	return 0, -1
}

func postJSON(url string, payload any, dst any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	if dst == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return err
	}
	return nil
}
