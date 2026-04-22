package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sandbox/internals/audit"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
	"time"

	suimodels "github.com/block-vision/sui-go-sdk/models"
	suiclient "github.com/block-vision/sui-go-sdk/sui"
	solanago "github.com/gagliardetto/solana-go"
	solanaata "github.com/gagliardetto/solana-go/programs/associated-token-account"
	solanasystem "github.com/gagliardetto/solana-go/programs/system"
	solanatoken "github.com/gagliardetto/solana-go/programs/token"
	solanarpc "github.com/gagliardetto/solana-go/rpc"
	"github.com/mr-tron/base58"
)

func handleTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedTransfer(&req)
	if err != nil {
		audit.LogEvent("tx_transfer", req.UID, RuntimeSandboxLabel, "failed", err.Error())
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

	audit.LogEvent("tx_transfer", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s to=%s amt=%s", res.Chain, res.To, res.AmountWei))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func executeManagedTransfer(req *TransferRequest) (*TransferResponse, error) {
	req.Chain = strings.ToLower(strings.TrimSpace(req.Chain))
	req.To = strings.TrimSpace(req.To)
	req.AmountWei = strings.TrimSpace(req.AmountWei)
	// 如果有Contract表示非native token
	req.TokenContract = strings.TrimSpace(req.TokenContract)
	if req.Chain == "" || req.To == "" || req.AmountWei == "" {
		return nil, errors.New("chain, to, and amount_wei are required")
	}
	if !isPublicChainEnabled(req.Chain) {
		return nil, errors.New(publicChainDisabledMessage(req.Chain))
	}
	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	from, err := utils.TransferFromAddress(req.Chain, addrSnapshot)
	if err != nil {
		return nil, err
	}

	intent := &policy.Intent{
		Chain:         req.Chain,
		SignMode:      "transaction",
		To:            req.To,
		AmountWei:     req.AmountWei,
		TokenContract: req.TokenContract,
	}
	if err := validateIntentWithRefreshForEvent(pe, intent, addrSnapshot, req.UID, "tx_transfer"); err != nil {
		return nil, err
	}

	switch {
	case signer.IsEVMChain(req.Chain):
		return executeManagedEVMTransfer(s, req, from, intent)
	case req.Chain == "solana":
		return executeManagedSolanaTransfer(s, req, from, intent)
	case req.Chain == "sui":
		return executeManagedSuiTransfer(s, req, from, intent)
	case req.Chain == "tron":
		return executeManagedTronTransfer(s, req, from, intent)
	case req.Chain == "bitcoin":
		return executeManagedBitcoinTransfer(s, req, from, intent)
	default:
		return nil, fmt.Errorf("managed transfer is not implemented for chain %q", req.Chain)
	}
}

func executeManagedEVMTransfer(s *signer.Signer, req *TransferRequest, from string, intent *policy.Intent) (*TransferResponse, error) {
	signReq := signer.SignRequest{
		Chain:          req.Chain,
		SignMode:       "transaction",
		BuilderKind:    "native_transfer",
		To:             req.To,
		AmountWei:      req.AmountWei,
		TokenContract:  req.TokenContract,
		UID:            req.UID,
		IsUserApproval: true,
		ApprovalID:     strings.TrimSpace(req.ApprovalID),
		ExecutionToken: strings.TrimSpace(req.ExecutionToken),
	}
	if req.TokenContract != "" {
		signReq.BuilderKind = "erc20_transfer"
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, err
	}

	build, err := buildStructuredEVMSigningPayload(req.Chain, from, &signReq)
	if err != nil {
		return nil, err
	}
	signReq.TxPayloadHex = build.TxPayloadHex

	res, err := s.Sign(&signReq)
	if err != nil {
		return nil, err
	}
	rawTxHex, err := AssembleSignedLegacyEVMTransaction(build, res.SignatureHex)
	if err != nil {
		return nil, err
	}
	broadcastRes, err := BroadcastSignedTransaction(&BroadcastRequest{
		Chain:    req.Chain,
		UID:      req.UID,
		RawTxHex: rawTxHex,
	})
	if err != nil {
		return nil, err
	}
	policyEngine.Commit(intent)

	return &TransferResponse{
		Chain:         req.Chain,
		From:          from,
		To:            intent.To,
		AmountWei:     intent.AmountWei,
		TokenContract: intent.TokenContract,
		SubmittedID:   broadcastRes.SubmittedID,
		TxHash:        broadcastRes.TxHash,
		TxPayloadHex:  build.TxPayloadHex,
		RawTxHex:      rawTxHex,
	}, nil
}

func executeManagedSolanaTransfer(s *signer.Signer, req *TransferRequest, from string, intent *policy.Intent) (*TransferResponse, error) {
	rpcURL, err := chainRPCURL("solana")
	if err != nil {
		return nil, err
	}
	rpcClient := solanarpc.New(rpcURL)

	fromKey, err := solanago.PublicKeyFromBase58(from)
	if err != nil {
		return nil, fmt.Errorf("invalid solana sender address: %w", err)
	}
	toKey, err := solanago.PublicKeyFromBase58(req.To)
	if err != nil {
		return nil, fmt.Errorf("invalid solana recipient address: %w", err)
	}
	amount, _ := new(big.Int).SetString(req.AmountWei, 10)
	if !amount.IsUint64() {
		return nil, errors.New("solana amount_wei exceeds uint64 lamport range")
	}

	recent, err := rpcClient.GetLatestBlockhash(context.Background(), solanarpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch solana blockhash: %w", err)
	}
	instructions := make([]solanago.Instruction, 0, 2)
	if req.TokenContract == "" {
		instructions = append(instructions, solanasystem.NewTransferInstruction(
			amount.Uint64(),
			fromKey,
			toKey,
		).Build())
	} else {
		mintKey, err := solanago.PublicKeyFromBase58(req.TokenContract)
		if err != nil {
			return nil, fmt.Errorf("invalid solana mint address: %w", err)
		}
		sourceATA, _, err := solanago.FindAssociatedTokenAddress(fromKey, mintKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive source ATA: %w", err)
		}
		destATA, _, err := solanago.FindAssociatedTokenAddress(toKey, mintKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive destination ATA: %w", err)
		}
		sourceBalance, err := rpcClient.GetTokenAccountBalance(context.Background(), sourceATA, solanarpc.CommitmentFinalized)
		if err != nil {
			return nil, fmt.Errorf("failed to read source token account: %w", err)
		}
		sourceRaw := strings.TrimSpace(sourceBalance.Value.Amount)
		sourceAmount, ok := new(big.Int).SetString(sourceRaw, 10)
		if !ok {
			return nil, errors.New("failed to parse source token balance")
		}
		if sourceAmount.Cmp(amount) < 0 {
			return nil, errors.New("insufficient SPL token balance")
		}
		destInfo, err := rpcClient.GetAccountInfo(context.Background(), destATA)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect destination token account: %w", err)
		}
		if destInfo == nil || destInfo.Value == nil {
			instructions = append(instructions, solanaata.NewCreateInstruction(fromKey, toKey, mintKey).Build())
		}
		instructions = append(instructions, solanatoken.NewTransferCheckedInstruction(
			amount.Uint64(),
			uint8(sourceBalance.Value.Decimals),
			sourceATA,
			mintKey,
			destATA,
			fromKey,
			nil,
		).Build())
	}

	// broadcastRes, err := BroadcastSignedTransaction(&BroadcastRequest{
	// 	Chain:       "solana",
	// 	UID:         req.UID,
	// 	RawTxBase64: rawTxBase64,
	// })
	var finalRawTxBase64 string
	builder := func(sponsorAddr string) (*BuildResult, error) {
		// a. 构建交易
		payerKey := fromKey
		if sponsorAddr != "" {
			sp, err := solanago.PublicKeyFromBase58(sponsorAddr)
			if err == nil {
				payerKey = sp
			}
		}

		tx, err := solanago.NewTransaction(
			instructions,
			recent.Value.Blockhash,
			solanago.TransactionPayer(payerKey),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to build solana transfer: %w", err)
		}

		rawTxBase64, err := signManagedSolanaTransaction(s, tx, &signer.SignRequest{
			UID:            req.UID,
			Chain:          "solana",
			SignMode:       "transaction",
			To:             req.To,
			TokenContract:  req.TokenContract,
			AmountWei:      req.AmountWei,
			IsUserApproval: true,
			ApprovalID:     strings.TrimSpace(req.ApprovalID),
			ExecutionToken: strings.TrimSpace(req.ExecutionToken),
		})
		if err != nil {
			return nil, err
		}
		finalRawTxBase64 = rawTxBase64
		sig := ""
		for i, account := range tx.Message.AccountKeys {
			if account.Equals(fromKey) && i < len(tx.Signatures) {
				sigBytes := tx.Signatures[i]
				if tx.Signatures[i].IsZero() {
					return nil, errors.New("solana user signature is zero")
				}
				sig = base58.Encode(sigBytes[:])
				break
			}
		}
		if sig == "" {
			return nil, errors.New("failed to locate solana user signature by from address")
		}
		return &BuildResult{TxBase64: rawTxBase64, Signature: sig}, nil
	}

	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       "solana",
		FromAddress: from,
		UID:         req.UID,
	}, builder)
	if err != nil {
		return nil, err
	}
	policyEngine.Commit(intent)

	return &TransferResponse{
		Chain:         "solana",
		From:          from,
		To:            req.To,
		AmountWei:     req.AmountWei,
		TokenContract: req.TokenContract,
		SubmittedID:   broadcastRes.SubmittedID,
		Signature:     broadcastRes.TxHash,
		RawTxBase64:   finalRawTxBase64,
		Sponsored:     broadcastRes.Sponsored,
	}, nil
}

func executeManagedSuiTransfer(s *signer.Signer, req *TransferRequest, from string, intent *policy.Intent) (*TransferResponse, error) {
	gasBudget := defaultSuiGasBudget(req.SuiGasBudget)
	gasBudgetInt, ok := new(big.Int).SetString(gasBudget, 10)
	if !ok || gasBudgetInt.Sign() <= 0 {
		return nil, errors.New("invalid sui gas budget")
	}
	rpcURL, err := chainRPCURL("sui")
	if err != nil {
		return nil, err
	}
	client := suiclient.NewSuiClient(rpcURL)
	requestedAmount, ok := new(big.Int).SetString(strings.TrimSpace(req.AmountWei), 10)
	if !ok || requestedAmount.Sign() <= 0 {
		return nil, errors.New("amount_wei must be a positive integer string")
	}
	var meta suimodels.TxnMetaData
	coinType := strings.TrimSpace(req.TokenContract)
	effectiveAmount := requestedAmount.String()
	var coinObjects []string

	if coinType == "" {
		coinType = "0x2::sui::SUI"
		totalSUI, err := getSuiTotalBalance(context.Background(), client, from)
		if err != nil {
			return nil, err
		}
		maxTransferable := new(big.Int).Sub(totalSUI, gasBudgetInt)
		if maxTransferable.Sign() <= 0 {
			return nil, errors.New("insufficient SUI balance to reserve gas")
		}
		amountToSend := new(big.Int).Set(requestedAmount)
		if requestedAmount.Cmp(totalSUI) == 0 {
			amountToSend = maxTransferable
		}
		if amountToSend.Cmp(maxTransferable) > 0 {
			return nil, fmt.Errorf("requested SUI amount exceeds spendable balance after gas reserve: requested=%s max=%s", amountToSend.String(), maxTransferable.String())
		}
		effectiveAmount = amountToSend.String()
		coinObjects, err = resolveSuiCoinObjectIDs(context.Background(), client, from, coinType, effectiveAmount)
		if err != nil {
			return nil, err
		}
		meta, err = client.PaySui(context.Background(), suimodels.PaySuiRequest{
			Signer:      from,
			SuiObjectId: coinObjects,
			Recipient:   []string{req.To},
			Amount:      []string{effectiveAmount},
			GasBudget:   gasBudget,
		})
		if strings.TrimSpace(meta.TxBytes) == "" {
			return nil, errors.New("failed to build sui coin transfer: empty txBytes")
		}
	} else {
		coinObjects, err = resolveSuiCoinObjectIDs(context.Background(), client, from, coinType, effectiveAmount)
		if err != nil {
			return nil, err
		}
	}

	builder := func(sponsorAddr string) (*BuildResult, error) {
		var meta suimodels.TxnMetaData
		var err error

		if sponsorAddr == "" {
			// 正常流程，自己支付Gas
			g, err := getSuiGasObjectID(context.Background(), client, from, gasBudget)
			if err != nil {
				return nil, err
			}
			if coinType == "0x2::sui::SUI" {
				meta, err = client.PaySui(context.Background(), suimodels.PaySuiRequest{
					Signer:      from,
					SuiObjectId: coinObjects,
					Recipient:   []string{req.To},
					Amount:      []string{effectiveAmount},
					GasBudget:   gasBudget,
				})
			} else {
				meta, err = client.Pay(context.Background(), suimodels.PayRequest{
					Signer:      from,
					SuiObjectId: coinObjects,
					Recipient:   []string{req.To},
					Amount:      []string{effectiveAmount},
					Gas:         &g,
					GasBudget:   gasBudget,
				})
			}
		} else {
			// 代付流程，Sponsor支付Gas，需手动构造PTB以设置GasOwner
			amountNeeded, _ := new(big.Int).SetString(effectiveAmount, 10)

			// 1. 调用封装方法直接拿到转账 PTB
			ptb, err := BuildSuiTransferPTB(context.Background(), client, from, req.To, coinType, amountNeeded.Uint64())
			if err != nil {
				return nil, err
			}

			// 2. 使用公共函数包装 Gas 和外壳
			txBase64, err := BuildSuiSponsoredTransaction(context.Background(), client, ptb, from, sponsorAddr, gasBudgetInt.Uint64())
			if err != nil {
				return nil, err
			}
			meta.TxBytes = txBase64
		}

		if err != nil {
			return nil, fmt.Errorf("failed to build sui coin transfer: %w", err)
		}
		if strings.TrimSpace(meta.TxBytes) == "" {
			return nil, errors.New("failed to build sui coin transfer: empty txBytes")
		}

		serializedSignature, err := signManagedSuiTransaction(s, meta.TxBytes, &signer.SignRequest{
			UID:           req.UID,
			SignMode:      "swap",
			To:            req.To,
			TokenContract: req.TokenContract,
			AmountWei:     effectiveAmount,
		})
		if err != nil {
			return nil, err
		}

		return &BuildResult{
			TxBase64:  meta.TxBytes,
			Signature: serializedSignature,
		}, nil
	}

	// 签名交易
	// serializedSignature, err := signManagedSuiTransaction(s, meta.TxBytes, &signer.SignRequest{
	// 	UID:            req.UID,
	// 	Chain:          "sui",
	// 	SignMode:       "transaction",
	// 	To:             req.To,
	// 	TokenContract:  req.TokenContract,
	// 	AmountWei:      effectiveAmount,
	// 	IsUserApproval: true,
	// 	ApprovalID:     strings.TrimSpace(req.ApprovalID),
	// 	ExecutionToken: strings.TrimSpace(req.ExecutionToken),
	// })
	if err != nil {
		return nil, err
	}
	// 发送交易
	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       "sui",
		FromAddress: from,
		UID:         req.UID,
	}, builder)
	if err != nil {
		return nil, err
	}
	policyEngine.Commit(intent)

	return &TransferResponse{
		Chain:         "sui",
		From:          from,
		To:            req.To,
		AmountWei:     effectiveAmount,
		TokenContract: coinType,
		SubmittedID:   broadcastRes.SubmittedID,
		Digest:        broadcastRes.SubmittedID,
		Sponsored:     broadcastRes.Sponsored,
	}, nil
}

// ====== ⬇️ helpers ⬇️ ======
func executeManagedTronTransfer(s *signer.Signer, req *TransferRequest, from string, intent *policy.Intent) (*TransferResponse, error) {
	if strings.TrimSpace(req.TokenContract) != "" {
		return nil, errors.New("tron managed transfer only supports native TRX")
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(req.AmountWei), 10)
	if !ok || amount.Sign() <= 0 {
		return nil, errors.New("amount_wei must be a positive integer string")
	}
	if !amount.IsInt64() {
		return nil, errors.New("tron amount_wei exceeds int64 range")
	}

	rpcURL, err := chainRPCURL("tron")
	if err != nil {
		return nil, err
	}
	rpcURL = strings.TrimRight(strings.TrimSpace(rpcURL), "/")

	var createRes struct {
		TxID       string `json:"txID"`
		Txid       string `json:"txid"`
		RawDataHex string `json:"raw_data_hex"`
		Message    string `json:"message"`
		Error      string `json:"Error"`
	}
	if err := postJSON(rpcURL+"/wallet/createtransaction", map[string]any{
		"owner_address": from,
		"to_address":    req.To,
		"amount":        amount.Int64(),
		"visible":       true,
	}, &createRes); err != nil {
		return nil, err
	}

	rawDataHex := strings.TrimSpace(createRes.RawDataHex)
	if rawDataHex == "" {
		reason := strings.TrimSpace(createRes.Message)
		if reason == "" {
			reason = strings.TrimSpace(createRes.Error)
		}
		if reason == "" {
			reason = "tron create transaction returned empty raw_data_hex"
		}
		return nil, errors.New(reason)
	}

	signReq := signer.SignRequest{
		Chain:        "tron",
		SignMode:     "transaction",
		TxPayloadHex: rawDataHex,
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, err
	}
	signRes, err := s.Sign(&signReq)
	if err != nil {
		return nil, err
	}

	signedTxHex, _, err := tronSignedTransactionHex(rawDataHex, []string{signRes.SignatureHex})
	if err != nil {
		return nil, err
	}
	broadcastRes, err := BroadcastSignedTransaction(&BroadcastRequest{
		Chain:     "tron",
		UID:       req.UID,
		RawTxHex:  rawDataHex,
		Signature: signRes.SignatureHex,
	})
	if err != nil {
		return nil, err
	}
	policyEngine.Commit(intent)

	txID := strings.TrimSpace(createRes.TxID)
	if txID == "" {
		txID = strings.TrimSpace(createRes.Txid)
	}
	if txID == "" {
		txID = broadcastRes.TxHash
	}

	return &TransferResponse{
		Chain:        "tron",
		From:         from,
		To:           req.To,
		AmountWei:    req.AmountWei,
		SubmittedID:  broadcastRes.SubmittedID,
		TxHash:       txID,
		Signature:    signRes.SignatureHex,
		TxPayloadHex: rawDataHex,
		RawTxHex:     signedTxHex,
	}, nil
}

func GetActiveSignerContext() (*signer.Signer, *policy.Engine, map[string]string, error) {
	mu.Lock()
	if sessionExpiredLocked() {
		ExpireActiveSessionLocked("ttl_expired")
	}
	if len(sekKey) == 0 &&
		masterPubKey != "" &&
		encShare1.Cipher == "" &&
		encShare3.Cipher != "" {
		if sek, err := loadSEKFromIdentityFile(env("IDENTITY_PATH", "identity.json")); err == nil {
			sekKey = sek
		} else {
			lockedReason = "sek_restore_failed"
		}
	}
	if (!activated || activeSigner == nil) &&
		masterPubKey != "" &&
		encShare1.Cipher == "" &&
		encShare3.Cipher != "" &&
		len(sekKey) > 0 {
		if err := activateWithSharePINLocked(hex.EncodeToString(sekKey)); err != nil {
			lockedReason = "reactivation_failed"
		}
	}
	isAct := activated
	s := activeSigner
	pe := policyEngine
	snapshot := make(map[string]string, len(addresses))
	for k, v := range addresses {
		snapshot[k] = v
	}
	mu.Unlock()

	if !isAct || s == nil {
		return nil, nil, nil, errors.New("locked")
	}
	return s, pe, snapshot, nil
}

// 验证share2门控并填充签名请求中的share2信息，如果门控未通过则返回对应错误
func PopulateSigningShares(req *signer.SignRequest) error {
	if req == nil {
		return errors.New("missing sign request")
	}
	mu.RLock()
	cachedLocalShare2 := localShare2
	mu.RUnlock()
	// 如果是需要审批的就不用缓存 必须过一次后端审核
	if !req.IsUserApproval && req.WrappedShare2 == "" && req.EncShare1.Cipher == "" && cachedLocalShare2.Cipher != "" {
		// Local phase1 wallets already have an encrypted second shard in memory after init.
		// Prefer that resident copy instead of unnecessarily round-tripping to the backend.
		req.EncShare1 = cachedLocalShare2
	}
	if req.WrappedShare2 == "" && req.EncShare1.Cipher == "" {
		wrappedShare2, share2Nonce, err := requestWrappedShare2ForSigning(req)
		if err == nil {
			req.WrappedShare2 = wrappedShare2
			req.Share2Nonce = share2Nonce
		} else if gateErr, ok := err.(*Share2GateError); ok {
			return gateErr
		} else {
			return err
		}
	}
	if req.WrappedShare2 == "" && req.EncShare1.Cipher == "" {
		return errors.New("unable to recover signing share")
	}
	return nil
}

func reportLocalBlockedIntent(uid string, intent *policy.Intent, reason string) {
	if intent == nil {
		return
	}
	target := strings.TrimRight(strings.TrimSpace(relayURL), "/")
	if target == "" {
		return
	}
	reportUID := strings.TrimSpace(uid)
	if reportUID == "" {
		mu.RLock()
		reportUID = strings.TrimSpace(boundUid)
		mu.RUnlock()
	}
	if reportUID == "" {
		return
	}
	intentPayloadBytes, _ := json.Marshal(struct {
		UID           string `json:"uid,omitempty"`
		Chain         string `json:"chain"`
		SignMode      string `json:"sign_mode"`
		To            string `json:"to,omitempty"`
		TokenContract string `json:"token_contract,omitempty"`
		AmountWei     string `json:"amount_wei,omitempty"`
	}{
		UID:           reportUID,
		Chain:         strings.ToLower(strings.TrimSpace(intent.Chain)),
		SignMode:      strings.TrimSpace(intent.SignMode),
		To:            strings.TrimSpace(intent.To),
		TokenContract: strings.TrimSpace(intent.TokenContract),
		AmountWei:     strings.TrimSpace(intent.AmountWei),
	})
	requestBody, _ := json.Marshal(struct {
		UID            string             `json:"uid"`
		Chain          string             `json:"chain"`
		SignMode       string             `json:"sign_mode"`
		IsUserApproval bool               `json:"is_user_approval"`
		ReasonCode     string             `json:"reason_code"`
		Reason         string             `json:"reason"`
		IntentPayload  string             `json:"intent_payload,omitempty"`
		Audit          share2AuditSummary `json:"audit"`
	}{
		UID:            reportUID,
		Chain:          strings.ToLower(strings.TrimSpace(intent.Chain)),
		SignMode:       strings.TrimSpace(intent.SignMode),
		IsUserApproval: true,
		ReasonCode:     "sandbox_policy_blocked",
		Reason:         strings.TrimSpace(reason),
		IntentPayload:  string(intentPayloadBytes),
		Audit: share2AuditSummary{
			To:            strings.TrimSpace(intent.To),
			AmountWei:     strings.TrimSpace(intent.AmountWei),
			TokenContract: strings.TrimSpace(intent.TokenContract),
			DecodedMethod: strings.TrimSpace(intent.SignMode),
			RiskFlags:     []string{"sandbox_policy_blocked"},
		},
	})
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Post(
		target+"/agent/tx/blocked",
		"application/json",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		log.Printf("[claw wallet sandbox] report local blocked intent failed uid=%s chain=%s err=%v", reportUID, intent.Chain, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[claw wallet sandbox] report local blocked intent rejected uid=%s chain=%s status=%d", reportUID, intent.Chain, resp.StatusCode)
	}
}

func chainRPCURL(chain string) (string, error) {
	rpcURL := env("CLAY_RPC_"+strings.ToUpper(strings.TrimSpace(chain)), "")
	if rpcURL != "" {
		return rpcURL, nil
	}
	rpcURL, ok := chainRPCEndpoints[strings.ToLower(strings.TrimSpace(chain))]
	if !ok {
		return "", fmt.Errorf("unsupported chain %q", chain)
	}
	return rpcURL, nil
}

func withSuiTransactionIntent(txBytes []byte) []byte {
	intent := []byte{0x00, 0x00, 0x00}
	payload := make([]byte, len(intent)+len(txBytes))
	copy(payload, intent)
	copy(payload[len(intent):], txBytes)
	return payload
}

func serializeSuiSignature(signatureHex, publicKeyHex string) (string, error) {
	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(signatureHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid sui signature hex: %w", err)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid sui public key hex: %w", err)
	}
	serialized := make([]byte, 1+len(signatureBytes)+len(publicKeyBytes))
	serialized[0] = 0x00
	copy(serialized[1:], signatureBytes)
	copy(serialized[1+len(signatureBytes):], publicKeyBytes)
	return base64.StdEncoding.EncodeToString(serialized), nil
}

func signManagedSolanaTransaction(s *signer.Signer, tx *solanago.Transaction, meta *signer.SignRequest) (string, error) {
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to encode solana message: %w", err)
	}

	signReq := signer.SignRequest{
		Chain:        "solana",
		SignMode:     "transaction",
		TxPayloadHex: "0x" + hex.EncodeToString(messageBytes),
	}
	if meta != nil {
		signReq.UID = strings.TrimSpace(meta.UID)
		signReq.IsUserApproval = meta.IsUserApproval
		signReq.ApprovalID = strings.TrimSpace(meta.ApprovalID)
		signReq.ExecutionToken = strings.TrimSpace(meta.ExecutionToken)
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return "", err
	}
	signRes, err := s.Sign(&signReq)
	if err != nil {
		return "", err
	}
	signatureBytes, err := hex.DecodeString(signRes.SignatureHex)
	if err != nil {
		return "", fmt.Errorf("invalid solana signature hex: %w", err)
	}
	if len(signatureBytes) != 64 {
		return "", fmt.Errorf("unexpected solana signature length %d", len(signatureBytes))
	}
	// Handle correct signature array length and positioning
	reqSigs := tx.Message.Header.NumRequiredSignatures
	if reqSigs == 0 {
		return "", errors.New("solana transaction requires 0 signatures")
	}

	// Ensure the Signatures slice is correctly sized
	if len(tx.Signatures) != int(reqSigs) {
		tx.Signatures = make([]solanago.Signature, int(reqSigs))
	}

	pubKeyBytes, err := hex.DecodeString(signRes.From)
	if err != nil {
		return "", fmt.Errorf("invalid solana signer public key hex: %w", err)
	}
	signerBase58 := solanago.PublicKeyFromBytes(pubKeyBytes).String()

	signerIndex := -1
	for i, account := range tx.Message.AccountKeys {
		if account.String() == signerBase58 {
			signerIndex = i
			break
		}
	}

	if signerIndex == -1 {
		return "", errors.New("failed to locate signer account in solana transaction message")
	}
	if signerIndex >= int(reqSigs) {
		return "", fmt.Errorf("signer index %d is outside required signature range %d", signerIndex, reqSigs)
	}
	copy(tx.Signatures[signerIndex][:], signatureBytes)

	rawTxBase64, err := tx.ToBase64()
	if err != nil {
		return "", fmt.Errorf("failed to serialize solana transaction: %w", err)
	}
	return rawTxBase64, nil
}

func signManagedSuiTransaction(s *signer.Signer, txBytesBase64 string, meta *signer.SignRequest) (string, error) {
	txBytes, err := base64.StdEncoding.DecodeString(txBytesBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode sui tx bytes: %w", err)
	}
	intentPayload := withSuiTransactionIntent(txBytes)

	signReq := signer.SignRequest{
		Chain:        "sui",
		SignMode:     "transaction",
		TxPayloadHex: "0x" + hex.EncodeToString(intentPayload),
	}
	if meta != nil {
		if strings.TrimSpace(meta.SignMode) != "" {
			signReq.SignMode = strings.TrimSpace(meta.SignMode)
		}
		signReq.UID = strings.TrimSpace(meta.UID)
		signReq.To = strings.TrimSpace(meta.To)
		signReq.TokenContract = strings.TrimSpace(meta.TokenContract)
		signReq.AmountWei = strings.TrimSpace(meta.AmountWei)
		signReq.Data = strings.TrimSpace(meta.Data)
		signReq.IsUserApproval = meta.IsUserApproval
		signReq.ApprovalID = strings.TrimSpace(meta.ApprovalID)
		signReq.ExecutionToken = strings.TrimSpace(meta.ExecutionToken)
	}
	// 再获取一次share2以确保签名时门控的最新状态，并填充到signReq中供后续签名使用
	if err := PopulateSigningShares(&signReq); err != nil {
		return "", err
	}
	signRes, err := s.Sign(&signReq)
	if err != nil {
		return "", err
	}
	return serializeSuiSignature(signRes.SignatureHex, signRes.From)
}

func resolveSuiCoinObjectIDs(ctx context.Context, client suiclient.ISuiAPI, owner, coinType, amount string) ([]string, error) {
	coins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    owner,
		CoinType: coinType,
		Limit:    50,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sui coin objects: %w", err)
	}
	targetAmount, ok := new(big.Int).SetString(amount, 10)
	if !ok || targetAmount.Sign() <= 0 {
		return nil, errors.New("amount_wei must be a positive integer string")
	}
	selected := make([]string, 0, len(coins.Data))
	accumulated := new(big.Int)
	for _, coin := range coins.Data {
		coinAmount, ok := new(big.Int).SetString(strings.TrimSpace(coin.Balance), 10)
		if !ok || coinAmount.Sign() <= 0 {
			continue
		}
		selected = append(selected, coin.CoinObjectId)
		accumulated.Add(accumulated, coinAmount)
		if accumulated.Cmp(targetAmount) >= 0 {
			return selected, nil
		}
	}
	return nil, fmt.Errorf("insufficient sui coin balance for %s", coinType)
}

func getSuiTotalBalance(ctx context.Context, client suiclient.ISuiAPI, owner string) (*big.Int, error) {
	coins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    owner,
		CoinType: "0x2::sui::SUI",
		Limit:    50,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sui balance: %w", err)
	}
	total := big.NewInt(0)
	for _, coin := range coins.Data {
		coinAmount, ok := new(big.Int).SetString(strings.TrimSpace(coin.Balance), 10)
		if !ok || coinAmount.Sign() <= 0 {
			continue
		}
		total.Add(total, coinAmount)
	}
	return total, nil
}

func getSuiGasObjectID(ctx context.Context, client suiclient.ISuiAPI, owner, amount string) (string, error) {
	coins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    owner,
		CoinType: "0x2::sui::SUI",
		Limit:    50,
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch sui coin objects: %w", err)
	}
	targetAmount, ok := new(big.Int).SetString(amount, 10)
	if !ok || targetAmount.Sign() <= 0 {
		return "", errors.New("amount_wei must be a positive integer string")
	}
	for _, coin := range coins.Data {
		coinAmount, ok := new(big.Int).SetString(strings.TrimSpace(coin.Balance), 10)
		if !ok || coinAmount.Sign() <= 0 {
			continue
		}
		if coinAmount.Cmp(targetAmount) >= 0 {
			return coin.CoinObjectId, nil
		}
	}
	return "", fmt.Errorf("insufficient sui coin balance for %s", amount)
}

func defaultSuiGasBudget(gasBudget string) string {
	gasBudget = strings.TrimSpace(gasBudget)
	if gasBudget != "" {
		return gasBudget
	}
	return env("CLAW_WALLET_SUI_GAS_BUDGET", "8000000")
}
