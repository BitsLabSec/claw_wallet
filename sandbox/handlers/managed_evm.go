package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sandbox/internals/audit"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// TODO:如果后续文件增长 考虑加入到handlers/evm下进行模块划分

// evm EIP-1559 模式
func HandleManagedEVMInvokeEIP1559(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ManagedEVMInvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedEVMInvokeEIP1559(&req)
	if err != nil {
		audit.LogEvent("tx_evm_invoke_eip1559", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		if gateErr, ok := err.(*Share2GateError); ok {
			http.Error(w, gateErr.reason, gateErr.status)
			return
		}
		if isAssetRefreshTimeout(err) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.LogEvent("tx_evm_invoke_eip1559", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s id=%s", res.Chain, res.SubmittedID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// evm 通用
func HandleManagedEVMInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ManagedEVMInvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedEVMInvoke(&req)
	if err != nil {
		audit.LogEvent("tx_evm_invoke", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		if gateErr, ok := err.(*Share2GateError); ok {
			http.Error(w, gateErr.reason, gateErr.status)
			return
		}
		if isAssetRefreshTimeout(err) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.LogEvent("tx_evm_invoke", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s id=%s", res.Chain, res.SubmittedID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func executeManagedEVMInvoke(req *ManagedEVMInvokeRequest) (*ManagedEVMTxResponse, error) {
	if req == nil {
		return nil, errors.New("missing request")
	}
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		chain = "bsc"
	}
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("unsupported chain %q", chain)
	}

	to := strings.TrimSpace(req.To)
	if to == "" {
		return nil, errors.New("to address is required, contract creation is not allowed")
	}

	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	from, err := utils.TransferFromAddress(chain, addrSnapshot)
	if err != nil {
		return nil, err
	}

	dataHex := strings.TrimPrefix(strings.TrimSpace(req.Data), "0x")
	var dataBytes []byte
	if dataHex != "" {
		dataBytes, err = hex.DecodeString(dataHex)
		if err != nil {
			return nil, fmt.Errorf("invalid data: %w", err)
		}
	}

	valueStr := strings.TrimSpace(req.Value)
	if valueStr == "" {
		valueStr = "0"
	}
	value, ok := new(big.Int).SetString(valueStr, 10)
	if !ok {
		return nil, errors.New("invalid value")
	}

	nonce, err := EvmRPCUint64(chain, "eth_getTransactionCount", []interface{}{from, "pending"})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}

	build, err := BuildLegacyEVMTxPayload(chain, from, to, value, dataBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to build tx payload: %w", err)
	}

	return executeManagedEVMInvokeWithBuild(req, chain, from, to, valueStr, dataBytes, build, pe, s, addrSnapshot)
}

func executeManagedEVMInvokeEIP1559(req *ManagedEVMInvokeRequest) (*ManagedEVMTxResponse, error) {
	if req == nil {
		return nil, errors.New("missing request")
	}
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		chain = "bsc"
	}
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("unsupported chain %q", chain)
	}

	to := strings.TrimSpace(req.To)
	if to == "" {
		return nil, errors.New("to address is required, contract creation is not allowed")
	}

	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	from, err := utils.TransferFromAddress(chain, addrSnapshot)
	if err != nil {
		return nil, err
	}

	dataHex := strings.TrimPrefix(strings.TrimSpace(req.Data), "0x")
	var dataBytes []byte
	if dataHex != "" {
		dataBytes, err = hex.DecodeString(dataHex)
		if err != nil {
			return nil, fmt.Errorf("invalid data: %w", err)
		}
	}

	valueStr := strings.TrimSpace(req.Value)
	if valueStr == "" {
		valueStr = "0"
	}
	value, ok := new(big.Int).SetString(valueStr, 10)
	if !ok {
		return nil, errors.New("invalid value")
	}

	nonce, err := EvmRPCUint64(chain, "eth_getTransactionCount", []interface{}{from, "pending"})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}

	build, err := BuildEIP1559EVMTxPayload(chain, from, to, value, dataBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to build EIP-1559 tx payload: %w", err)
	}

	return executeManagedEVMInvokeWithBuild(req, chain, from, to, valueStr, dataBytes, build, pe, s, addrSnapshot)
}

func executeManagedEVMInvokeWithBuild(req *ManagedEVMInvokeRequest, chain, from, to, valueStr string, dataBytes []byte, build *EvmStructuredBuild, pe *policy.Engine, s *signer.Signer, addrSnapshot map[string]string) (*ManagedEVMTxResponse, error) {
	if err := SimulateEVMCall(chain, from, to, build.Value, dataBytes); err != nil {
		return nil, err
	}
	signMode := normalizeManagedSignMode(req.SignMode)

	signReq := signer.SignRequest{
		Chain:           chain,
		SignMode:        signMode,
		UID:             strings.TrimSpace(req.UID),
		TxPayloadHex:    build.TxPayloadHex,
		To:              to,
		AmountWei:       valueStr,
		Data:            "0x" + hex.EncodeToString(dataBytes),
		ConfirmedByUser: req.ConfirmedByUser,
	}

	pi := &policy.Intent{Chain: chain, SignMode: signMode, To: to, AmountWei: valueStr}
	if strings.HasPrefix(signReq.Data, "0xa9059cbb") && len(signReq.Data) >= 138 {
		toPart := signReq.Data[34:74]
		amtPart := strings.TrimLeft(signReq.Data[74:138], "0")
		if amtPart == "" {
			amtPart = "0"
		}
		val, _ := new(big.Int).SetString(amtPart, 16)
		pi.TokenContract = pi.To
		pi.To = "0x" + toPart
		pi.AmountWei = val.String()
	}

	activePolicy := pe.Current()
	if !activePolicy.AllowBlindSign {
		assessment, err := signer.AssessAuditability(&signReq)
		if err != nil {
			return nil, err
		}
		if assessment.Enforceable && !assessment.Auditable {
			reason := "blind payload blocked"
			if assessment.Reason != "" {
				reason = assessment.Reason
			}
			return nil, errors.New(reason)
		}
	}

	if err := validateIntentWithRefreshForEvent(pe, pi, addrSnapshot, req.UID, "tx_evm_invoke"); err != nil {
		return nil, err
	}

	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, err
	}

	var finalSignatureHex string
	var finalRawTxHex string

	builder := func(_ string) (*BuildResult, error) {
		res, err := s.Sign(&signReq)
		if err != nil {
			return nil, err
		}
		var rawTx string
		if build.BuilderKind == "eip1559" {
			rawTx, err = assembleSignedEVMTransaction(build.TxPayloadHex, res.SignatureHex)
		} else {
			rawTx, err = AssembleSignedLegacyEVMTransaction(build, res.SignatureHex)
		}
		if err != nil {
			return nil, err
		}
		finalSignatureHex = res.SignatureHex
		finalRawTxHex = rawTx
		return &BuildResult{TxBase64: rawTx, Signature: res.SignatureHex}, nil
	}

	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       chain,
		FromAddress: from,
		UID:         req.UID,
	}, builder)
	if err != nil {
		return nil, err
	}
	pe.Commit(pi)

	return &ManagedEVMTxResponse{
		Chain:       chain,
		From:        from,
		To:          pi.To,
		Value:       pi.AmountWei,
		SubmittedID: broadcastRes.SubmittedID,
		TxHash:      broadcastRes.TxHash,
		Signature:   finalSignatureHex,
		TxPayload:   build.TxPayloadHex,
		RawTxHex:    finalRawTxHex,
		Sponsored:   broadcastRes.Sponsored,
	}, nil
}

func assembleSignedEVMTransaction(txPayloadHex, signatureHex string) (string, error) {
	payload, err := DecodeHex(txPayloadHex)
	if err != nil {
		return "", fmt.Errorf("invalid tx_payload_hex: %w", err)
	}
	sig, err := hexutil.Decode(signatureHex)
	if err != nil {
		return "", fmt.Errorf("invalid signature_hex: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("ethereum signature must be 65 bytes")
	}
	if sig[64] > 1 {
		return "", fmt.Errorf("unsupported recovery id %d", sig[64])
	}

	txType := byte(0x00)
	raw := payload
	if len(payload) > 0 && payload[0] < 0xc0 {
		txType = payload[0]
		switch txType {
		case 0x01, 0x02:
			if len(payload) == 1 {
				return "", errors.New("typed tx missing rlp body")
			}
			raw = payload[1:]
		default:
			return "", fmt.Errorf("unsupported typed tx prefix: 0x%02x", txType)
		}
	}

	var elems []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &elems); err != nil {
		return "", fmt.Errorf("rlp decode failed: %w", err)
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	yParity := uint(sig[64])

	switch txType {
	case 0x00:
		if len(elems) != 6 && len(elems) != 9 {
			return "", fmt.Errorf("legacy signing payload must have 6 or 9 rlp elements, got %d", len(elems))
		}

		var v *big.Int
		if len(elems) == 6 {
			v = new(big.Int).SetUint64(uint64(27 + sig[64]))
		} else {
			var chainID big.Int
			if err := rlp.DecodeBytes(elems[6], &chainID); err != nil {
				return "", fmt.Errorf("decode chainId failed: %w", err)
			}
			v = new(big.Int).Mul(&chainID, big.NewInt(2))
			v.Add(v, big.NewInt(int64(35+sig[64])))
		}

		encV, err := rlp.EncodeToBytes(v)
		if err != nil {
			return "", fmt.Errorf("rlp encode v failed: %w", err)
		}
		encR, err := rlp.EncodeToBytes(r)
		if err != nil {
			return "", fmt.Errorf("rlp encode r failed: %w", err)
		}
		encS, err := rlp.EncodeToBytes(s)
		if err != nil {
			return "", fmt.Errorf("rlp encode s failed: %w", err)
		}

		out := make([]rlp.RawValue, 0, 9)
		out = append(out, elems[:6]...)
		out = append(out, rlp.RawValue(encV), rlp.RawValue(encR), rlp.RawValue(encS))
		rawTx, err := rlp.EncodeToBytes(out)
		if err != nil {
			return "", fmt.Errorf("failed to assemble signed legacy transaction: %w", err)
		}
		return "0x" + hex.EncodeToString(rawTx), nil
	case 0x01:
		if len(elems) != 8 {
			return "", fmt.Errorf("eip2930 signing payload must have 8 rlp elements, got %d", len(elems))
		}
		yEnc, err := rlp.EncodeToBytes(yParity)
		if err != nil {
			return "", fmt.Errorf("rlp encode yParity failed: %w", err)
		}
		rEnc, err := rlp.EncodeToBytes(r)
		if err != nil {
			return "", fmt.Errorf("rlp encode r failed: %w", err)
		}
		sEnc, err := rlp.EncodeToBytes(s)
		if err != nil {
			return "", fmt.Errorf("rlp encode s failed: %w", err)
		}

		out := make([]rlp.RawValue, 0, 11)
		out = append(out, elems...)
		out = append(out, rlp.RawValue(yEnc), rlp.RawValue(rEnc), rlp.RawValue(sEnc))
		rawTx, err := rlp.EncodeToBytes(out)
		if err != nil {
			return "", fmt.Errorf("failed to assemble signed eip2930 transaction: %w", err)
		}
		return "0x01" + hex.EncodeToString(rawTx), nil
	case 0x02:
		if len(elems) != 9 {
			return "", fmt.Errorf("eip1559 signing payload must have 9 rlp elements, got %d", len(elems))
		}
		yEnc, err := rlp.EncodeToBytes(yParity)
		if err != nil {
			return "", fmt.Errorf("rlp encode yParity failed: %w", err)
		}
		rEnc, err := rlp.EncodeToBytes(r)
		if err != nil {
			return "", fmt.Errorf("rlp encode r failed: %w", err)
		}
		sEnc, err := rlp.EncodeToBytes(s)
		if err != nil {
			return "", fmt.Errorf("rlp encode s failed: %w", err)
		}

		out := make([]rlp.RawValue, 0, 12)
		out = append(out, elems...)
		out = append(out, rlp.RawValue(yEnc), rlp.RawValue(rEnc), rlp.RawValue(sEnc))
		rawTx, err := rlp.EncodeToBytes(out)
		if err != nil {
			return "", fmt.Errorf("failed to assemble signed eip1559 transaction: %w", err)
		}
		return "0x02" + hex.EncodeToString(rawTx), nil
	default:
		return "", fmt.Errorf("unsupported evm tx type: 0x%02x", txType)
	}
}

func normalizeManagedSignMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", "transaction":
		return "transaction"
	case "swap":
		return "swap"
	case "bridge":
		return "bridge"
	default:
		return mode
	}
}
