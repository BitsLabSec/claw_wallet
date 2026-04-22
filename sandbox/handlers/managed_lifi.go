package handlers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var lifiTaskStatusMap sync.Map // map[string]*LifiStatusResponse
var lifiTaskStateMu sync.RWMutex
var lifiLatestTaskUID string

const (
	lifiBaseURL    = "https://li.quest/v1"
	suiChainIDStr  = "9270000000000000"
	solChainIDStr  = "1151111081099710"
	solanaUSDCAddr = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" // Solana 涓婄殑 USDC
	lifiOrderMode  = "CHEAPEST"
)

var lifiTaskRetention = 30 * time.Minute

func storeLifiTaskStatus(uid string, status *LifiStatusResponse) {
	uid = strings.TrimSpace(uid)
	if uid == "" || status == nil {
		return
	}
	lifiTaskStatusMap.Store(uid, status)
}

func setLatestLifiTaskUID(uid string) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	lifiTaskStateMu.Lock()
	lifiLatestTaskUID = uid
	lifiTaskStateMu.Unlock()
}

func getLatestLifiTaskUID() string {
	lifiTaskStateMu.RLock()
	uid := strings.TrimSpace(lifiLatestTaskUID)
	lifiTaskStateMu.RUnlock()
	return uid
}

// isLifiEVMChain reports whether the chain ID is one of LI.FI's common EVM chains.
func isLifiEVMChain(chainID string) bool {
	evmChains := map[string]bool{
		"1": true, "42161": true, "10": true, "8453": true, "137": true, "56": true,
		"43114": true, "59144": true, "534352": true, "100": true, "324": true, "143": true,
	}
	return evmChains[chainID]
}

// getLifiChainNameByID maps LI.FI chain IDs to internal chain names.
func getLifiChainNameByID(chainID string) string {
	switch chainID {
	case "1":
		return "ethereum"
	case "42161":
		return "arbitrum"
	case "10":
		return "optimism"
	case "8453":
		return "base"
	case "137":
		return "polygon"
	case "56":
		return "bsc"
	case "43114":
		return "avalanche"
	case "59144":
		return "linea"
	case "534352":
		return "scroll"
	case "100":
		return "gnosis"
	case "324":
		return "zksync"
	case "143":
		return "monad"
	case "1151111081099710":
		return "solana"
	case "9270000000000000":
		return "sui"
	case "20000000000001":
		return "bitcoin"
	default:
		return ""
	}
}

type lifiQuoteAPIResponse struct {
	Code          any    `json:"code,omitempty"`
	Msg           string `json:"message,omitempty"`
	Tool          string `json:"tool"`
	IncludedSteps []struct {
		Type   string `json:"type"`
		Tool   string `json:"tool"`
		Action struct {
			FromToken struct {
				Address  string `json:"address"`
				Symbol   string `json:"symbol"`
				Decimals int    `json:"decimals"`
			} `json:"fromToken"`
			ToToken struct {
				Address  string `json:"address"`
				Symbol   string `json:"symbol"`
				Decimals int    `json:"decimals"`
			} `json:"toToken"`
		} `json:"action"`
		Estimate struct {
			ExecutionDuration float64 `json:"executionDuration"`
		} `json:"estimate"`
	} `json:"includedSteps"`
	Estimate struct {
		ToAmount          string  `json:"toAmount"`
		ExecutionDuration float64 `json:"executionDuration"`
		ToToken           struct {
			Address  string `json:"address"`
			Symbol   string `json:"symbol"`
			Decimals int    `json:"decimals"`
		} `json:"toToken"`
	} `json:"estimate"`
	Action struct {
		FromToken struct {
			Address  string `json:"address"`
			Symbol   string `json:"symbol"`
			Decimals int    `json:"decimals"`
		} `json:"fromToken"`
		ToToken struct {
			Address  string `json:"address"`
			Symbol   string `json:"symbol"`
			Decimals int    `json:"decimals"`
		} `json:"toToken"`
		FromAmount string `json:"fromAmount"`
	} `json:"action"`
	TransactionRequest struct {
		To       string `json:"to"`
		Data     string `json:"data"`
		Value    string `json:"value"`
		GasLimit string `json:"gasLimit"`
		GasPrice string `json:"gasPrice"`
		ChainId  int64  `json:"chainId"`
	} `json:"transactionRequest"`
}

type lifiErrorDetail struct {
	Code    any    `json:"code"`
	Message string `json:"message"`
}

type lifiErrorResponse struct {
	Code    any             `json:"code"`
	Message string          `json:"message"`
	Errors  json.RawMessage `json:"errors"`
}

type lifiErrorObjectPayload struct {
	FilteredOut []struct {
		OverallPath string `json:"overallPath"`
		Reason      string `json:"reason"`
	} `json:"filteredOut"`
	Failed []struct {
		OverallPath string `json:"overallPath"`
		Subpaths    map[string][]struct {
			ErrorType string `json:"errorType"`
			Code      any    `json:"code"`
			Tool      string `json:"tool"`
			Message   string `json:"message"`
		} `json:"subpaths"`
	} `json:"failed"`
}

type lifiStatusAPIResponse struct {
	Status    string `json:"status"`
	Substatus string `json:"substatus"`
}

func scheduleLifiTaskCleanup(uid string) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	time.AfterFunc(lifiTaskRetention, func() {
		lifiTaskStatusMap.Delete(uid)
		lifiTaskStateMu.Lock()
		if strings.EqualFold(strings.TrimSpace(lifiLatestTaskUID), uid) {
			lifiLatestTaskUID = ""
		}
		lifiTaskStateMu.Unlock()
	})
}

func ensureLifiBridgeSupported(req *LifiBridgeRequest) error {
	if req == nil {
		return nil
	}
	if req.FromChainID == "20000000000001" || req.ToChainID == "20000000000001" {
		return errors.New("bitcoin is not supported for LI.FI bridge yet")
	}
	return nil
}

func fetchLifiQuote(fromChain, toChain, fromToken, toToken, amount, fromAddress, toAddress string, slippage float64) (*lifiQuoteAPIResponse, error) {
	query := url.Values{}
	query.Set("fromChain", strings.TrimSpace(fromChain))
	query.Set("toChain", strings.TrimSpace(toChain))
	query.Set("fromToken", strings.TrimSpace(fromToken))
	query.Set("toToken", strings.TrimSpace(toToken))
	query.Set("fromAmount", strings.TrimSpace(amount))
	query.Set("fromAddress", strings.TrimSpace(fromAddress))
	query.Set("toAddress", strings.TrimSpace(toAddress))
	query.Set("order", lifiOrderMode)
	if slippage > 0 {
		query.Set("slippage", strconv.FormatFloat(slippage, 'f', -1, 64))
	}
	apiKey, integrator, fee, shouldSetIntegratorBundle := resolveLifiIntegratorBundle()
	if shouldSetIntegratorBundle {
		query.Set("integrator", integrator)
		query.Set("fee", fee)
	}
	reqURL := fmt.Sprintf("%s/quote?%s", lifiBaseURL, query.Encode())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	if shouldSetIntegratorBundle {
		req.Header.Set("x-lifi-api-key", apiKey)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lifi quote request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, parseLifiQuoteError(resp.StatusCode, body)
	}

	var quote lifiQuoteAPIResponse
	if err := json.Unmarshal(body, &quote); err != nil {
		return nil, fmt.Errorf("failed to parse lifi quote response: %w", err)
	}

	return &quote, nil
}

func resolveLifiIntegratorBundle() (string, string, string, bool) {
	apiKey := strings.TrimSpace(env("LIFI_API_KEY", ""))
	integrator := strings.TrimSpace(env("LIFI_INTEGRATOR", ""))
	fee := strings.TrimSpace(env("LIFI_FEE", ""))
	enabled := apiKey != "" && integrator != "" && fee != ""
	return apiKey, integrator, fee, enabled
}

func parseLifiQuoteError(httpStatus int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = "unknown LI.FI error"
	}

	var payload lifiErrorResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("lifi quote api error: http=%d, body=%s", httpStatus, msg)
	}

	code := normalizeLifiErrorCode(payload.Code)
	message := strings.TrimSpace(payload.Message)
	detailCodes, detailMessages := extractLifiErrorDetails(payload.Errors)
	detailCode := pickPrimaryLifiCode(detailCodes)
	detailMessage := strings.Join(detailMessages, " ; ")
	if code == "" {
		code = detailCode
	}
	if message == "" {
		message = detailMessage
	}
	if detailMessage != "" && message != detailMessage {
		message = message + " | detail: " + detailMessage
	}
	if message == "" {
		message = msg
	}
	hint := lifiTroubleshootingHint(code, message)
	if code != "" {
		return fmt.Errorf("lifi quote failed (http=%d, code=%s): %s. Hint: %s", httpStatus, code, message, hint)
	}
	return fmt.Errorf("lifi quote failed (http=%d): %s. Hint: %s", httpStatus, message, hint)
}

func extractLifiErrorDetails(raw json.RawMessage) ([]string, []string) {
	if len(raw) == 0 {
		return nil, nil
	}

	// 兼容旧格式: errors 为数组
	var arr []lifiErrorDetail
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		codes := make([]string, 0, len(arr))
		messages := make([]string, 0, len(arr))
		for _, item := range arr {
			code := normalizeLifiErrorCode(item.Code)
			msg := strings.TrimSpace(item.Message)
			if code != "" {
				codes = appendUniqueString(codes, code)
			}
			if msg != "" {
				messages = appendUniqueString(messages, buildLifiErrorLabel("", code, msg))
			}
		}
		return codes, messages
	}

	// 兼容新格式: errors 为对象，包含 filteredOut / failed
	var obj lifiErrorObjectPayload
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil
	}

	var codes []string
	var messages []string
	for _, item := range obj.FilteredOut {
		if reason := strings.TrimSpace(item.Reason); reason != "" {
			tool := inferLifiToolFromPath(item.OverallPath)
			messages = appendUniqueString(messages, buildLifiErrorLabel(tool, "", reason))
		}
	}

	for _, failed := range obj.Failed {
		for _, subpathErrors := range failed.Subpaths {
			for _, e := range subpathErrors {
				code := normalizeLifiErrorCode(e.Code)
				msg := strings.TrimSpace(e.Message)
				tool := strings.TrimSpace(e.Tool)
				if tool == "" {
					tool = inferLifiToolFromPath(failed.OverallPath)
				}
				if code != "" {
					codes = appendUniqueString(codes, code)
				}
				if msg != "" {
					messages = appendUniqueString(messages, buildLifiErrorLabel(tool, code, msg))
				}
			}
		}
	}
	return codes, messages
}

func buildLifiErrorLabel(tool, code, message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	labelParts := make([]string, 0, 2)
	if strings.TrimSpace(tool) != "" {
		labelParts = append(labelParts, strings.TrimSpace(tool))
	}
	if strings.TrimSpace(code) != "" {
		labelParts = append(labelParts, strings.TrimSpace(code))
	}
	if len(labelParts) == 0 {
		return message
	}
	return fmt.Sprintf("[%s] %s", strings.Join(labelParts, ":"), message)
}

func inferLifiToolFromPath(overallPath string) string {
	path := strings.ToLower(strings.TrimSpace(overallPath))
	if path == "" {
		return ""
	}
	knownTools := []string{
		"allbridge",
		"mayanfastmctp",
		"mayanmctp",
		"debridge",
		"stargate",
		"hop",
		"across",
		"cbridge",
		"hyphen",
	}
	for _, tool := range knownTools {
		if strings.Contains(path, tool) {
			return tool
		}
	}
	return ""
}

func appendUniqueString(list []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return list
	}
	for _, item := range list {
		if item == value {
			return list
		}
	}
	return append(list, value)
}

func pickPrimaryLifiCode(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	priority := []string{
		"AMOUNT_TOO_LOW",
		"AMOUNT_TOO_HIGH",
		"NO_POSSIBLE_ROUTE",
		"INSUFFICIENT_LIQUIDITY",
		"TOOL_TIMEOUT",
		"CHAIN_NOT_SUPPORTED",
		"1007",
	}
	for _, p := range priority {
		for _, c := range codes {
			if c == p {
				return c
			}
		}
	}
	return codes[0]
}

func normalizeLifiErrorCode(code any) string {
	switch v := code.(type) {
	case string:
		return strings.TrimSpace(strings.ToUpper(v))
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}

func lifiTroubleshootingHint(code, message string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	msg := strings.ToLower(strings.TrimSpace(message))
	switch {
	case code == "1001":
		return "No route could generate an executable transaction. Common causes are amount too low or insufficient spendable balance (including gas). Try increasing from_amount and make sure the source wallet has enough token balance and native gas."
	case code == "NO_POSSIBLE_ROUTE":
		return "No route is currently available for this token pair or chain combination. Try another token, reduce the amount, or use a staged route."
	case code == "AMOUNT_TOO_LOW":
		return "The amount is too low. Increase from_amount and try again."
	case code == "AMOUNT_TOO_HIGH":
		return "The amount is too high. Split into smaller transactions or reduce the amount."
	case code == "INSUFFICIENT_LIQUIDITY":
		return "Insufficient liquidity. Reduce the amount, increase slippage, or retry later."
	case code == "TOOL_TIMEOUT":
		return "A third-party bridge/aggregator timed out. Retry later or switch route."
	case code == "CHAIN_NOT_SUPPORTED":
		return "This chain combination is not supported. Choose a supported route."
	case code == "1007" || strings.Contains(msg, "return amount is not enough") || strings.Contains(msg, "exchange rate has changed"):
		return "Slippage failure caused by price movement. Increase slippage moderately and retry."
	case strings.Contains(msg, "insufficient") && strings.Contains(msg, "balance"):
		return "Insufficient balance. Ensure fromAddress has enough token balance and gas."
	default:
		return "Check liquidity, slippage, balance, and destination chain availability, then retry."
	}
}

func formatTokenAmount(raw string, decimals int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return raw
	}
	if decimals <= 0 {
		return n.String()
	}
	negative := n.Sign() < 0
	if negative {
		n = new(big.Int).Abs(n)
	}
	base := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	intPart := new(big.Int).Quo(n, base).String()
	fracPart := new(big.Int).Mod(n, base).String()
	if len(fracPart) < decimals {
		fracPart = strings.Repeat("0", decimals-len(fracPart)) + fracPart
	}
	fracPart = strings.TrimRight(fracPart, "0")
	out := intPart
	if fracPart != "" {
		out = intPart + "." + fracPart
	}
	if negative {
		return "-" + out
	}
	return out
}

func waitForLifiCrossChain(txHash, fromChain, toChain, uid string) (string, string) {
	startTime := time.Now()
	statusURL := fmt.Sprintf("%s/status?txHash=%s&fromChain=%s&toChain=%s", lifiBaseURL, txHash, fromChain, toChain)

	client := &http.Client{Timeout: 10 * time.Second}
	for {
		if time.Since(startTime) > 3*time.Minute {
			return "TIMEOUT_CONTINUE_LATER", statusURL
		}

		req, _ := http.NewRequest("GET", statusURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var status lifiStatusAPIResponse
			if err := json.Unmarshal(body, &status); err == nil {
				// 鏇存柊寮傛浠诲姟鐘舵€侊紝鏂逛究鍓嶇杞
				if uid != "" {
					if val, ok := lifiTaskStatusMap.Load(uid); ok {
						taskResp := val.(*LifiStatusResponse)
						taskResp.Message = fmt.Sprintf("閾句笂鐘舵€? %s, 瀛愮姸鎬? %s (鑰楁椂: %v)", status.Status, status.Substatus, time.Since(startTime).Round(time.Second))
						lifiTaskStatusMap.Store(uid, taskResp)
					}
				}

				if status.Status == "DONE" {
					return "DONE", statusURL
				} else if status.Status == "FAILED" {
					return "FAILED", statusURL
				}
			}
		}

		time.Sleep(15 * time.Second)
	}
}

func executeLifiTransaction(uid string, quote *lifiQuoteAPIResponse, chainName string) (string, error) {
	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return "", err
	}
	_ = s
	_ = pe
	fromAddress, err := utils.TransferFromAddress(chainName, addrSnapshot)
	if err != nil {
		return "", err
	}

	if chainName == "sui" {
		txData := quote.TransactionRequest.Data
		if strings.HasPrefix(txData, "0x") {
			txDataBytes, _ := hex.DecodeString(strings.TrimPrefix(txData, "0x"))
			txData = base64.StdEncoding.EncodeToString(txDataBytes)
		}
		intent := &policy.Intent{
			Chain:         "sui",
			SignMode:      "bridge",
			To:            strings.TrimSpace(quote.TransactionRequest.To),
			AmountWei:     strings.TrimSpace(quote.Action.FromAmount),
			TokenContract: strings.TrimSpace(quote.Action.FromToken.Address),
		}
		if strings.EqualFold(intent.TokenContract, "0x0000000000000000000000000000000000000000") {
			intent.TokenContract = ""
		}
		res, err := executeManagedHaedalTxBytes(uid, txData, &signer.SignRequest{
			UID:           uid,
			SignMode:      "bridge",
			To:            intent.To,
			TokenContract: intent.TokenContract,
			AmountWei:     intent.AmountWei,
		}, intent)
		if err != nil {
			return "", err
		}
		return res.Digest, nil
	}

	if chainName == "solana" {
		req := &ManagedSolInvokeRequest{
			UID:      uid,
			Chain:    chainName,
			SignMode: "bridge",
			Data:     quote.TransactionRequest.Data,
			To:       strings.TrimSpace(quote.TransactionRequest.To),
			Value:    strings.TrimSpace(quote.Action.FromAmount),
		}
		res, err := executeManagedSolInvoke(req)
		if err != nil {
			return "", err
		}
		return res.TxHash, nil
	}

	// EVM Chain
	tokenAddress := quote.Action.FromToken.Address
	amountIn := new(big.Int)
	amountIn.SetString(quote.Action.FromAmount, 10)
	router := quote.TransactionRequest.To

	// Check allowance if not native token
	if tokenAddress != "0x0000000000000000000000000000000000000000" && tokenAddress != "" {
		allowance, err := evmERC20Allowance(chainName, tokenAddress, fromAddress, router)
		if err != nil {
			return "", fmt.Errorf("failed to check allowance: %w", err)
		}
		if allowance.Cmp(amountIn) < 0 {
			approveData, err := buildERC20ApproveCalldata(router, amountIn)
			if err != nil {
				return "", fmt.Errorf("failed to build approve data: %w", err)
			}
			approveReq := &ManagedEVMInvokeRequest{
				UID:             uid,
				Chain:           chainName,
				SignMode:        "bridge",
				To:              tokenAddress,
				Value:           "0",
				Data:            "0x" + hex.EncodeToString(approveData),
				ConfirmedByUser: true, // Force confirmation so the approval leg can bypass first-transfer gate.
			}
			approveRes, err := executeManagedEVMInvokeEIP1559(approveReq)
			if err != nil {
				return "", fmt.Errorf("failed to execute approve: %w", err)
			}
			if err := waitForERC20Allowance(chainName, tokenAddress, fromAddress, router, amountIn, approveRes.TxHash, "lifi approval", nil); err != nil {
				return "", fmt.Errorf(
					"approve sent but allowance not ready for swap: %w (approve_tx_hash=%s token=%s owner=%s spender=%s target=%s)",
					err,
					strings.TrimSpace(approveRes.TxHash),
					strings.TrimSpace(tokenAddress),
					strings.TrimSpace(fromAddress),
					strings.TrimSpace(router),
					amountIn.String(),
				)
			}
		}
	}

	hexValue := quote.TransactionRequest.Value
	valueStr := "0"
	if hexValue != "" {
		if strings.HasPrefix(hexValue, "0x") {
			if val, ok := new(big.Int).SetString(hexValue[2:], 16); ok {
				valueStr = val.String()
			}
		} else {
			if val, ok := new(big.Int).SetString(hexValue, 10); ok {
				valueStr = val.String()
			}
		}
	}

	swapReq := &ManagedEVMInvokeRequest{
		UID:             uid,
		Chain:           chainName,
		SignMode:        "bridge",
		To:              router,
		Value:           valueStr,
		Data:            quote.TransactionRequest.Data,
		ConfirmedByUser: true, // Force confirmation so the swap leg can bypass first-transfer gate.
	}
	res, err := executeManagedEVMInvokeEIP1559(swapReq)
	if err != nil {
		return "", fmt.Errorf("failed to execute swap: %w", err)
	}
	return res.TxHash, nil
}

func HandleLifiBridgeTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chains := r.URL.Query().Get("chains")
	if chains == "" {
		http.Error(w, "chains parameter is required", http.StatusBadRequest)
		return
	}

	reqURL := fmt.Sprintf("%s/tokens?chains=%s", lifiBaseURL, chains)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch lifi tokens: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func HandleLifiBridgeQuote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LifiBridgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedLifiQuote(&req)
	if err != nil {
		json.NewEncoder(w).Encode(&LifiQuoteResponse{
			IsSuccess: false,
			Reason:    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func HandleLifiBridgeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LifiStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	taskUID := strings.TrimSpace(req.UID)
	if taskUID == "" {
		http.Error(w, "uid is required", http.StatusBadRequest)
		return
	}

	val, ok := lifiTaskStatusMap.Load(taskUID)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&LifiStatusResponse{
			Status:  "NOT_FOUND",
			Message: "can not found bridge task of UID",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(val.(*LifiStatusResponse))
}

func HandleLifiBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LifiBridgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	taskUID := uuid.NewString()

	storeLifiTaskStatus(taskUID, &LifiStatusResponse{
		Status:  "PENDING",
		Message: "bridge tx init...",
	})
	setLatestLifiTaskUID(taskUID)
	scheduleLifiTaskCleanup(taskUID)

	resultChan := make(chan *LifiStatusResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				failed := &LifiStatusResponse{
					Status:  "FAILED",
					Message: fmt.Sprintf("panic: %v", r),
				}
				storeLifiTaskStatus(taskUID, failed)
				resultChan <- failed
			}
		}()

		resp, err := executeManagedLifiSwap(&req, boundUid, taskUID)
		var finalStatus *LifiStatusResponse
		if err != nil {
			finalStatus = &LifiStatusResponse{
				Status:  "FAILED",
				Message: err.Error(),
			}
		} else {
			status := "DONE"
			if !resp.Success {
				status = "FAILED"
			}
			finalStatus = &LifiStatusResponse{
				Status:         status,
				Message:        resp.Message,
				Steps:          resp.Steps,
				FinalTxHash:    resp.FinalTxHash,
				FinalStatusURL: resp.FinalStatusURL,
			}
		}

		storeLifiTaskStatus(taskUID, finalStatus)
		select {
		case resultChan <- finalStatus:
		default:
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	select {
	case res := <-resultChan:
		json.NewEncoder(w).Encode(&LifiBridgeResponse{
			UID:            taskUID,
			Success:        res.Status == "DONE",
			Status:         res.Status,
			Message:        res.Message,
			Steps:          res.Steps,
			FinalTxHash:    res.FinalTxHash,
			FinalStatusURL: res.FinalStatusURL,
		})
	case <-time.After(30 * time.Second):
		json.NewEncoder(w).Encode(&LifiBridgeResponse{
			UID:     taskUID,
			Success: false,
			Status:  "PENDING",
			Message: fmt.Sprintf("bridge is executing. please call /api/v1/tx/bridge/lifi/status with uid: %s to check status until it become to DONE or FAILED.", taskUID),
		})
	}
}

func executeManagedLifiSwap(req *LifiBridgeRequest, identityUID string, taskUID string) (*LifiBridgeResponse, error) {
	if req == nil {
		return nil, errors.New("missing swap request")
	}
	if strings.TrimSpace(identityUID) == "" {
		return nil, errors.New("wallet uid is not bound")
	}
	if err := ensureLifiBridgeSupported(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.FromChainID) != "" && strings.TrimSpace(req.FromChainID) == strings.TrimSpace(req.ToChainID) {
		return executeManagedLifiSameChainSwap(req, identityUID, taskUID)
	}

	_, _, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	fromChainName := getLifiChainNameByID(req.FromChainID)
	sandboxFromAddress, err := utils.TransferFromAddress(fromChainName, addrSnapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to get sandbox from_address: %v", err)
	}
	if !strings.EqualFold(sandboxFromAddress, req.FromAddress) {
		return nil, fmt.Errorf("address mismatch: provided from_address %s does not match sandbox address %s for chain %s", req.FromAddress, sandboxFromAddress, fromChainName)
	}

	fromAddress := req.FromAddress
	toAddress := req.ToAddress
	needsSolanaTransit := req.ViaSolana && isLifiEVMChain(req.FromChainID) && req.ToChainID == suiChainIDStr

	var steps []LifiExecuteStep
	var finalTxHash string
	var finalStatusURL string

	if needsSolanaTransit {
		solanaAddress, err := utils.TransferFromAddress("solana", addrSnapshot)
		if err != nil {
			return nil, fmt.Errorf("failed to get solana address: %v", err)
		}

		quote1, err := fetchLifiQuote(req.FromChainID, solChainIDStr, req.FromToken, solanaUSDCAddr, req.Amount, fromAddress, solanaAddress, req.Slippage)
		if err != nil {
			return nil, fmt.Errorf("stage 1 (EVM -> SOL) quote failed: %v", err)
		}

		txHash1, err := executeLifiTransaction(identityUID, quote1, fromChainName)
		if err != nil {
			return nil, fmt.Errorf("stage 1 execution failed: %v", err)
		}

		status1, url1 := waitForLifiCrossChain(txHash1, req.FromChainID, solChainIDStr, taskUID)
		steps = append(steps, LifiExecuteStep{
			FromChainID: req.FromChainID,
			ToChainID:   solChainIDStr,
			TxHash:      txHash1,
			Status:      status1,
			StatusURL:   url1,
		})
		if status1 != "DONE" {
			return &LifiBridgeResponse{
				UID:     taskUID,
				Success: false,
				Status:  "FAILED",
				Message: "stage 1 (EVM->SOL) bridge timed out or failed",
				Steps:   steps,
			}, nil
		}

		quote2, err := fetchLifiQuote(solChainIDStr, req.ToChainID, solanaUSDCAddr, req.ToToken, quote1.Estimate.ToAmount, solanaAddress, toAddress, req.Slippage)
		if err != nil {
			return nil, fmt.Errorf("stage 2 (SOL -> SUI) quote failed: %v", err)
		}

		txHash2, err := executeLifiTransaction(identityUID, quote2, "solana")
		if err != nil {
			return nil, fmt.Errorf("stage 2 execution failed: %v", err)
		}

		status2, url2 := waitForLifiCrossChain(txHash2, solChainIDStr, req.ToChainID, taskUID)
		steps = append(steps, LifiExecuteStep{
			FromChainID: solChainIDStr,
			ToChainID:   req.ToChainID,
			TxHash:      txHash2,
			Status:      status2,
			StatusURL:   url2,
		})
		finalTxHash = txHash2
		finalStatusURL = url2
		if status2 != "DONE" {
			return &LifiBridgeResponse{
				UID:     taskUID,
				Success: false,
				Status:  "FAILED",
				Message: "stage 2 (SOL->SUI) bridge timed out or failed",
				Steps:   steps,
			}, nil
		}
	} else {
		quote, err := fetchLifiQuote(req.FromChainID, req.ToChainID, req.FromToken, req.ToToken, req.Amount, fromAddress, toAddress, req.Slippage)
		if err != nil {
			return nil, fmt.Errorf("quote failed: %v", err)
		}

		txHash, err := executeLifiTransaction(identityUID, quote, fromChainName)
		if err != nil {
			return nil, fmt.Errorf("execution failed: %v", err)
		}

		status, url := waitForLifiCrossChain(txHash, req.FromChainID, req.ToChainID, taskUID)
		steps = append(steps, LifiExecuteStep{
			FromChainID: req.FromChainID,
			ToChainID:   req.ToChainID,
			TxHash:      txHash,
			Status:      status,
			StatusURL:   url,
		})
		finalTxHash = txHash
		finalStatusURL = url
		if status != "DONE" {
			return &LifiBridgeResponse{
				UID:     taskUID,
				Success: false,
				Status:  "FAILED",
				Message: "bridge timed out or failed",
				Steps:   steps,
			}, nil
		}
	}

	return &LifiBridgeResponse{
		UID:            taskUID,
		Success:        true,
		Status:         "DONE",
		Message:        "bridge executed successfully",
		Steps:          steps,
		FinalTxHash:    finalTxHash,
		FinalStatusURL: finalStatusURL,
	}, nil
}

// uniswap 熔断机制 如果uniswap 失败了 就会退到lifi 上面做同链交换 但是如果用户指定了 from_chain_id 和 to_chain_id 就必须相同 否则就报错
func executeManagedLifiSameChainSwap(req *LifiBridgeRequest, identityUID, taskUID string) (*LifiBridgeResponse, error) {
	if req == nil {
		return nil, errors.New("missing swap request")
	}
	if strings.TrimSpace(identityUID) == "" {
		return nil, errors.New("wallet uid is not bound")
	}
	if strings.TrimSpace(taskUID) == "" {
		return nil, errors.New("missing li.fi task uid")
	}
	if err := ensureLifiBridgeSupported(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.FromChainID) == "" || strings.TrimSpace(req.FromChainID) != strings.TrimSpace(req.ToChainID) {
		return nil, errors.New("li.fi same-chain swap requires identical from_chain_id and to_chain_id")
	}

	_, _, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	fromChainName := getLifiChainNameByID(req.FromChainID)
	if fromChainName == "" {
		return nil, fmt.Errorf("unsupported li.fi chain id for same-chain swap: %s", req.FromChainID)
	}

	sandboxFromAddress, err := utils.TransferFromAddress(fromChainName, addrSnapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to get sandbox from_address: %v", err)
	}
	if !strings.EqualFold(sandboxFromAddress, req.FromAddress) {
		return nil, fmt.Errorf("address mismatch: provided from_address %s does not match sandbox address %s for chain %s", req.FromAddress, sandboxFromAddress, fromChainName)
	}

	quote, err := fetchLifiQuote(req.FromChainID, req.ToChainID, req.FromToken, req.ToToken, req.Amount, req.FromAddress, req.ToAddress, req.Slippage)
	if err != nil {
		return nil, fmt.Errorf("same-chain quote failed: %v", err)
	}

	txHash, err := executeLifiTransaction(identityUID, quote, fromChainName)
	if err != nil {
		return nil, fmt.Errorf("same-chain execution failed: %v", err)
	}

	return &LifiBridgeResponse{
		UID:     taskUID,
		Success: true,
		Status:  "DONE",
		Message: "swap transaction submitted",
		Steps: []LifiExecuteStep{
			{
				FromChainID: req.FromChainID,
				ToChainID:   req.ToChainID,
				TxHash:      txHash,
				Status:      "SUBMITTED",
			},
		},
		FinalTxHash: txHash,
	}, nil
}

func executeManagedLifiQuote(req *LifiBridgeRequest) (*LifiQuoteResponse, error) {
	if req == nil {
		return nil, errors.New("missing quote request")
	}
	if err := ensureLifiBridgeSupported(req); err != nil {
		return nil, err
	}

	fromAddress := req.FromAddress
	toAddress := req.ToAddress

	if fromAddress == "" || toAddress == "" {
		_, _, addrSnapshot, err := GetActiveSignerContext()
		if err == nil {
			fromChainName := getLifiChainNameByID(req.FromChainID)
			toChainName := getLifiChainNameByID(req.ToChainID)
			if fromAddress == "" {
				fromAddress, _ = utils.TransferFromAddress(fromChainName, addrSnapshot)
			}
			if toAddress == "" {
				toAddress, _ = utils.TransferFromAddress(toChainName, addrSnapshot)
			}
		}
	}

	if fromAddress == "" || toAddress == "" {
		return nil, errors.New("from_address and to_address are required")
	}

	if req.ViaSolana && isLifiEVMChain(req.FromChainID) && req.ToChainID == suiChainIDStr {
		solAddress := ""
		_, _, addrSnapshot, err := GetActiveSignerContext()
		if err == nil {
			solAddress, _ = utils.TransferFromAddress("solana", addrSnapshot)
		}
		if solAddress == "" {
			return nil, errors.New("failed to determine intermediate solana address")
		}

		quote1, err := fetchLifiQuote(req.FromChainID, solChainIDStr, req.FromToken, solanaUSDCAddr, req.Amount, fromAddress, solAddress, req.Slippage)
		if err != nil {
			return nil, fmt.Errorf("stage 1 (EVM->Solana) route quote failed: %v", err)
		}

		quote2, err := fetchLifiQuote(solChainIDStr, suiChainIDStr, solanaUSDCAddr, req.ToToken, quote1.Estimate.ToAmount, solAddress, toAddress, req.Slippage)
		if err != nil {
			return nil, fmt.Errorf("stage 2 (Solana->Sui) route quote failed: %v", err)
		}

		var steps []LifiRouteStep
		for _, s := range quote1.IncludedSteps {
			steps = append(steps, LifiRouteStep{
				Tool:          s.Tool,
				FromToken:     s.Action.FromToken.Symbol,
				ToToken:       s.Action.ToToken.Symbol,
				EstimatedTime: s.Estimate.ExecutionDuration,
			})
		}
		for _, s := range quote2.IncludedSteps {
			steps = append(steps, LifiRouteStep{
				Tool:          s.Tool,
				FromToken:     s.Action.FromToken.Symbol,
				ToToken:       s.Action.ToToken.Symbol,
				EstimatedTime: s.Estimate.ExecutionDuration,
			})
		}

		return &LifiQuoteResponse{
			IsSuccess:         true,
			Tool:              fmt.Sprintf("%s + %s", quote1.Tool, quote2.Tool),
			Steps:             steps,
			EstimatedDuration: quote1.Estimate.ExecutionDuration + quote2.Estimate.ExecutionDuration,
			AmountIn:          formatTokenAmount(quote1.Action.FromAmount, quote1.Action.FromToken.Decimals),
			AmountOut:         formatTokenAmount(quote2.Estimate.ToAmount, quote2.Estimate.ToToken.Decimals),
			AmountInRaw:       quote1.Action.FromAmount,
			AmountOutRaw:      quote2.Estimate.ToAmount,
			AmountInSymbol:    quote1.Action.FromToken.Symbol,
			AmountOutSymbol:   quote2.Estimate.ToToken.Symbol,
			AmountInDecimals:  quote1.Action.FromToken.Decimals,
			AmountOutDecimals: quote2.Estimate.ToToken.Decimals,
		}, nil
	}

	quote, err := fetchLifiQuote(req.FromChainID, req.ToChainID, req.FromToken, req.ToToken, req.Amount, fromAddress, toAddress, req.Slippage)
	if err != nil {
		return nil, fmt.Errorf("route quote failed: %v", err)
	}

	var steps []LifiRouteStep
	for _, s := range quote.IncludedSteps {
		steps = append(steps, LifiRouteStep{
			Tool:          s.Tool,
			FromToken:     s.Action.FromToken.Symbol,
			ToToken:       s.Action.ToToken.Symbol,
			EstimatedTime: s.Estimate.ExecutionDuration,
		})
	}

	return &LifiQuoteResponse{
		IsSuccess:         true,
		Tool:              quote.Tool,
		Steps:             steps,
		EstimatedDuration: quote.Estimate.ExecutionDuration,
		AmountIn:          formatTokenAmount(quote.Action.FromAmount, quote.Action.FromToken.Decimals),
		AmountOut:         formatTokenAmount(quote.Estimate.ToAmount, quote.Estimate.ToToken.Decimals),
		AmountInRaw:       quote.Action.FromAmount,
		AmountOutRaw:      quote.Estimate.ToAmount,
		AmountInSymbol:    quote.Action.FromToken.Symbol,
		AmountOutSymbol:   quote.Estimate.ToToken.Symbol,
		AmountInDecimals:  quote.Action.FromToken.Decimals,
		AmountOutDecimals: quote.Estimate.ToToken.Decimals,
	}, nil
}
