package handlers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sandbox/internals/audit"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
)

// TODO:如果后续文件增长 考虑加入到handlers/sol下进行模块划分

// solana 通用调用接口
func handleManagedSolInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ManagedSolInvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedSolInvoke(&req)
	if err != nil {
		audit.LogEvent("tx_sol_invoke", req.UID, RuntimeSandboxLabel, "failed", err.Error())
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

	audit.LogEvent("tx_sol_invoke", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s id=%s", res.Chain, res.SubmittedID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func executeManagedSolInvoke(req *ManagedSolInvokeRequest) (*ManagedSolTxResponse, error) {
	if req == nil {
		return nil, errors.New("missing request")
	}
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		chain = "solana"
	}
	if chain != "solana" {
		return nil, fmt.Errorf("unsupported chain %q for solana logic", chain)
	}

	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}
	from, err := utils.TransferFromAddress(chain, addrSnapshot)
	if err != nil {
		return nil, err
	}
	unsignedPayload, err := resolveSolanaUnsignedPayload(req)
	if err != nil {
		return nil, err
	}

	return executeManagedSolInvokeWithPayload(req, chain, from, unsignedPayload, pe, s, addrSnapshot)
}

func executeManagedSolInvokeWithPayload(req *ManagedSolInvokeRequest, chain, from string, unsignedPayload []byte, pe *policy.Engine, s *signer.Signer, addrSnapshot map[string]string) (*ManagedSolTxResponse, error) {
	to := strings.TrimSpace(req.To)
	if to == "" {
		to = from
	}
	valueStr := strings.TrimSpace(req.Value)
	if valueStr == "" {
		valueStr = "0"
	}
	signMode := normalizeManagedSignMode(req.SignMode)

	signReq := signer.SignRequest{
		Chain:           chain,
		SignMode:        signMode,
		UID:             strings.TrimSpace(req.UID),
		TxPayloadHex:    "0x" + hex.EncodeToString(unsignedPayload),
		To:              to,
		AmountWei:       valueStr,
		ConfirmedByUser: req.ConfirmedByUser,
	}

	pi := &policy.Intent{Chain: chain, SignMode: signMode, To: to, AmountWei: valueStr}

	// 这里可以针对 SPL Token 逻辑做解析并重写 pi.TokenContract 和 pi.To
	// 类似 EVM 的 ERC20 Transfer 解析

	activePolicy := pe.Current()
	if !activePolicy.AllowBlindSign {
		assessment, err := signer.AssessAuditability(&signReq)
		if err != nil {
			return nil, err
		}
		if assessment.Enforceable && !assessment.Auditable {
			reason := "solana blind payload blocked"
			if assessment.Reason != "" {
				reason = assessment.Reason
			}
			return nil, errors.New(reason)
		}
	}

	if err := validateIntentWithRefreshForEvent(pe, pi, addrSnapshot, req.UID, "tx_sol_invoke"); err != nil {
		return nil, err
	}

	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, err
	}

	var finalRawTxBase64 string
	var finalSignature string

	builder := func(sponsorAddr string) (*BuildResult, error) {
		effectiveMessageBytes := unsignedPayload
		if strings.TrimSpace(sponsorAddr) != "" {
			rebuiltMessageBytes, err := solanaRebuildMessageWithSponsorPayer(unsignedPayload, from, sponsorAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to rebuild solana invoke message with sponsor payer: %w", err)
			}
			effectiveMessageBytes = rebuiltMessageBytes
		}
		effectiveTxBytes, err := solanaBuildUnsignedTxBytesFromMessage(effectiveMessageBytes)
		if err != nil {
			return nil, err
		}
		signedTxBytes, serializedSignature, err := solanaSignAndAttachSignatureByAddress(s, effectiveTxBytes, effectiveMessageBytes, from)
		if err != nil {
			return nil, err
		}
		rawTxBase64 := base64.StdEncoding.EncodeToString(signedTxBytes)

		userSignatureBase58, err := extractSolanaSignatureBase58ByAddressFromRawTxBase64(rawTxBase64, from)
		if err != nil {
			return nil, err
		}

		finalRawTxBase64 = rawTxBase64
		finalSignature = serializedSignature
		return &BuildResult{
			TxBase64: rawTxBase64,
			// 此处只返回代付所需的base58形式不影响 普通用户自己支付的场景
			// 因为普通场景下仅需要rawTxBase64
			Signature: userSignatureBase58,
		}, nil
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

	return &ManagedSolTxResponse{
		Chain:       chain,
		From:        from,
		To:          pi.To,
		Value:       pi.AmountWei,
		SubmittedID: broadcastRes.SubmittedID,
		TxHash:      broadcastRes.TxHash,
		Signature:   finalSignature,
		TxPayload:   signReq.TxPayloadHex,
		RawTxBase64: finalRawTxBase64,
		Sponsored:   broadcastRes.Sponsored,
	}, nil
}

func resolveSolanaUnsignedPayload(req *ManagedSolInvokeRequest) ([]byte, error) {
	base64Candidate := strings.TrimSpace(req.UnsignedTxBase64)
	if base64Candidate == "" {
		base64Candidate = strings.TrimSpace(req.TxPayloadBase64)
	}
	if base64Candidate == "" {
		base64Candidate = strings.TrimSpace(req.Data)
	}
	hexCandidate := strings.TrimSpace(req.UnsignedTxHex)
	if hexCandidate == "" {
		hexCandidate = strings.TrimSpace(req.TxPayloadHex)
	}
	if base64Candidate == "" && hexCandidate == "" {
		return nil, errors.New("unsigned transaction payload is required")
	}
	if base64Candidate != "" {
		payload, err := decodeBase64Payload(base64Candidate)
		if err != nil {
			return nil, fmt.Errorf("invalid unsigned_tx_base64: %w", err)
		}
		return payload, nil
	}
	payload, err := DecodeHex(hexCandidate)
	if err != nil {
		return nil, fmt.Errorf("invalid unsigned_tx_hex: %w", err)
	}
	if len(payload) == 0 {
		return nil, errors.New("unsigned transaction payload is empty")
	}
	return payload, nil
}

func assembleSignedSolanaTransaction(unsignedPayload []byte, signatureHex string) (string, error) {
	sigBytes, err := DecodeHex(signatureHex)
	if err != nil {
		return "", fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != 64 {
		return "", fmt.Errorf("solana signature must be 64 bytes, got %d", len(sigBytes))
	}
	rawTxBytes := make([]byte, 0, 1+len(sigBytes)+len(unsignedPayload))
	rawTxBytes = append(rawTxBytes, 0x01)
	rawTxBytes = append(rawTxBytes, sigBytes...)
	rawTxBytes = append(rawTxBytes, unsignedPayload...)
	return base64.StdEncoding.EncodeToString(rawTxBytes), nil
}
