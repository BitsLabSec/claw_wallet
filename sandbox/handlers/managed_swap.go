package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sandbox/internals/audit"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	solanago "github.com/gagliardetto/solana-go"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
)

const solanaWSOLMint = "So11111111111111111111111111111111111111112"
const defaultUniswapTradeAPIURL = "https://trade-api.gateway.uniswap.org/v1"
const defaultJupiterQuoteURL = "https://api.jup.ag/swap/v1/quote"
const defaultJupiterSwapURL = "https://api.jup.ag/swap/v1/swap"
const defaultJupiterTokenSearchURL = "https://api.jup.ag/tokens/search"
const defaultCetusFindRoutesURL = "https://api-sui.cetus.zone/router_v3/find_routes"
const defaultCetusSwapV3URL = "https://api-sui-mcp.cetus.zone/aggregator/swap_v3"
const evmPermit2Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
const evmNativeTokenAddress = "0x0000000000000000000000000000000000000000"

var cetusAllowedAPIHosts = map[string]struct{}{
	"api-sui.cetus.zone":     {},
	"api-sui-mcp.cetus.zone": {},
}

var solanaCommonTokenMints = map[string]string{
	"SOL":  solanaWSOLMint,
	"WSOL": solanaWSOLMint,
	"USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
	"USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
}

var evmUniversalRouterByChain = map[string][]string{
	"ethereum":  {"0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af", "0x4c82d1fBfE28c977cbb58d8C7ff8fcF9F70A2Cca"},
	"optimism":  {"0x851116D9223fAbED8E56C0E6B8Ad0c31d98B3507", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
	"bsc":       {"0x1906c1D672b88cd1B9ac7593301ca990F94Eae07", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
	"base":      {"0x6ff5693b99212Da76ad316178A184aB56D299b43", "0xfdf682F51fE81aa4898F0Ae2163D8A55C127Fbc7"},
	"arbitrum":  {"0xa51afAFE0263b40Edaef0df8781eA9Aa03E381a3", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
	"polygon":   {"0x1095692a6237D83C6a72F3f5efEDb9a670C49223", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
	"avalanche": {"0x94b75331Ae8D42c1B61065089b7D48fE14aa73B7", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
	"linea":     {"0x661e93ccA42AfACb172121EF892830ca3b70f08D", "0x8b844f885672f333bc0042cb669255f93a4c1e6b"},
}

var evmCommonTokenByChain = map[string]map[string]string{
	"ethereum": {
		"USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
		"USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
		"DAI":  "0x6B175474E89094C44Da98b954EedeAC495271d0F",
	},
	"base": {
		"USDC": "0x833589fCD6EDB6E08f4c7C32D4f71b54bdA02913",
	},
	"optimism": {
		"USDT": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",
		"USDC": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
	},
	"arbitrum": {
		"USDT": "0xFd086bC7CD5C481DCC9C85ebe478A1C0b69FCbb9",
		"USDC": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
		"WBTC": "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
	},
	"polygon": {
		"USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
		"USDC": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
		"WBTC": "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6",
	},
	"bsc": {
		"USDT": "0x55d398326f99059fF775485246999027B3197955",
		"USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
		"ETH":  "0x2170Ed0880ac9A755fd29B2688956BD959F933F8",
		"BTCB": "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c",
	},
	"avalanche": {
		"USDT": "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7",
		"USDC": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
	},
	"linea": {
		"USDT": "0xA219439258ca9da29E9Cc4cE5596924745e12B93",
		"USDC": "0x176211869cA2b568f2A7D4EE941E073a821EE1ff",
	},
}

var uniswapChainIDByChain = map[string]int{
	"ethereum":  1,
	"optimism":  10,
	"bsc":       56,
	"polygon":   137,
	"monad":     143,
	"base":      8453,
	"arbitrum":  42161,
	"avalanche": 43114,
	"zksync":    324,
	"linea":     59144,
}

var jupiterProgramAllowlist = map[string]struct{}{
	"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": {},
	"JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB": {},
}

type uniswapTradeAPICallError struct {
	path      string
	retryable bool
	err       error
}

func (e *uniswapTradeAPICallError) Error() string {
	if e == nil || e.err == nil {
		return "uniswap trade api error"
	}
	return e.err.Error()
}

func (e *uniswapTradeAPICallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// uniswap 入口
func handleUniswapSwap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UniswapSwapTradeAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedUniswapSwap(&req)
	if err != nil {
		audit.LogEvent("tx_swap_uniswap", req.UID, RuntimeSandboxLabel, "failed", err.Error())
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

	audit.LogEvent("tx_swap_uniswap", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s routing=%s token_in=%s token_out=%s amt_in=%s", res.Chain, res.Routing, res.TokenIn, res.TokenOut, res.AmountInWei))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// 执行Uniswap 交换的核心逻辑，包含审批检查、报价获取、交易执行等步骤
func executeManagedUniswapSwap(req *UniswapSwapTradeAPIRequest) (*UniswapSwapTradeAPIResponse, error) {
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("uniswap swap only supports EVM chains, got %q", req.Chain)
	}
	// 获取 Uniswap 交易所需的 chainID
	chainID, err := uniswapChainID(chain)
	if err != nil {
		return nil, err
	}
	if uniswapAPIKey() == "" {
		return nil, errors.New("missing uniswap api key")
	}

	amountIn := new(big.Int)
	if _, ok := amountIn.SetString(strings.TrimSpace(req.AmountInWei), 10); !ok || amountIn.Sign() <= 0 {
		return nil, errors.New("amount_in_wei must be a positive integer string")
	}
	tokenIn, isNativeIn, err := normalizeUniswapTokenAddress(chain, req.TokenIn, true)
	if err != nil {
		return nil, fmt.Errorf("invalid token_in: %w", err)
	}
	if strings.TrimSpace(req.TokenOut) == "" {
		return nil, errors.New("token_out is required")
	}
	tokenOut, isNativeOut, err := normalizeUniswapTokenAddress(chain, req.TokenOut, true)
	if err != nil {
		return nil, fmt.Errorf("invalid token_out: %w", err)
	}
	// 获取当前签名者的地址，作为交易的发起者
	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}
	from, err := utils.TransferFromAddress(chain, addrSnapshot)
	if err != nil {
		return nil, err
	}

	res := &UniswapSwapTradeAPIResponse{
		Chain:       chain,
		From:        from,
		TokenIn:     tokenIn,
		TokenOut:    tokenOut,
		AmountInWei: amountIn.String(),
	}
	if isNativeIn {
		res.TokenIn = common.HexToAddress(evmNativeTokenAddress).Hex()
	}
	if isNativeOut {
		res.TokenOut = common.HexToAddress(evmNativeTokenAddress).Hex()
	}
	// 如果是erc20 token，先检查是否需要审批，并执行相应的审批交易
	if !isNativeIn {
		approvalAmount := new(big.Int).Mul(new(big.Int).Set(amountIn), big.NewInt(2))
		approvalResp, err := fetchUniswapApproval(&UniswapTradeApprovalRequest{
			WalletAddress:   from,
			Token:           tokenIn,
			Amount:          approvalAmount.String(),
			ChainID:         chainID,
			TokenOut:        tokenOut,
			TokenOutChainID: chainID,
		})
		if err != nil {
			// 熔断机制
			if shouldFallbackToLifi(err) {
				return executeManagedUniswapSwapViaLifi(req, chain, from, tokenIn, tokenOut, amountIn, err)
			}
			return nil, err
		}
		if approvalResp != nil {
			res.RequestID = strings.TrimSpace(approvalResp.RequestID)
			// 如果需要审批重置，先执行审批重置交易；如果需要审批，执行审批交易。审批重置和审批可能会是同一笔交易，也可能是两笔交易，取决于 Uniswap 的返回结果。
			if approvalResp.Cancel != nil {
				cancelTxRes, err := executeUniswapTradeTx(req.UID, chain, from, tokenIn, approvalResp.Cancel)
				if err != nil {
					return nil, fmt.Errorf("execute uniswap approval reset: %w", err)
				}
				res.ApprovalReset = buildUniswapTradeExecutionResult(approvalResp.Cancel, cancelTxRes)
			}
			if approvalResp.Approval != nil {
				approvalTxRes, err := executeUniswapTradeTx(req.UID, chain, from, tokenIn, approvalResp.Approval)
				if err != nil {
					return nil, fmt.Errorf("execute uniswap approval: %w", err)
				}
				res.ApprovalRequired = true
				res.Approval = buildUniswapTradeExecutionResult(approvalResp.Approval, approvalTxRes)
			}
		}
	}

	generatePermitAsTransaction := false
	quoteReq := &UniswapTradeQuoteRequest{
		Swapper:                     from,
		TokenInChainID:              chainID,
		TokenOutChainID:             chainID,
		TokenIn:                     tokenIn,
		TokenOut:                    tokenOut,
		Amount:                      amountIn.String(),
		Type:                        "EXACT_INPUT",
		RoutingPreference:           strings.TrimSpace(req.RoutingPreference),
		Protocols:                   normalizeUniswapProtocols(req.Protocols),
		Urgency:                     strings.TrimSpace(req.Urgency),
		PermitAmount:                normalizeUniswapPermitAmount(req.PermitAmount),
		GeneratePermitAsTransaction: &generatePermitAsTransaction,
	}
	if quoteReq.RoutingPreference == "" {
		quoteReq.RoutingPreference = "BEST_PRICE"
	}
	if quoteReq.PermitAmount == "" {
		quoteReq.PermitAmount = "FULL"
	}
	// 滑点
	if slippage := normalizeUniswapAutoSlippage(req.AutoSlippage); slippage != "" {
		quoteReq.AutoSlippage = slippage
	}
	if req.SlippageTolerance > 0 {
		val := int(req.SlippageTolerance)
		quoteReq.SlippageTolerance = &val
		quoteReq.AutoSlippage = ""
	}
	// 询价，获取 Uniswap 的报价和交易执行方案
	quoteResp, err := fetchUniswapQuote(quoteReq)
	if err != nil {
		// 熔断机制
		if shouldFallbackToLifi(err) {
			return executeManagedUniswapSwapViaLifi(req, chain, from, tokenIn, tokenOut, amountIn, err)
		}
		return nil, err
	}
	res.RequestID = firstNonEmpty(res.RequestID, strings.TrimSpace(quoteResp.RequestID))
	res.Routing = strings.ToUpper(strings.TrimSpace(quoteResp.Routing))
	// 签名
	permitSignature := ""
	if !isEmptyRawJSON(quoteResp.PermitData) {
		permitSignature, err = signUniswapPermitData(s, chain, req.UID, quoteResp.PermitData)
		if err != nil {
			return nil, err
		}
	}
	// 如果 Uniswap 返回需要执行审批交易（可能是审批重置，也可能是审批），先执行审批交易
	if quoteResp.PermitTransaction != nil {
		permitTxRes, err := executeUniswapTradeTx(req.UID, chain, from, tokenIn, quoteResp.PermitTransaction)
		if err != nil {
			return nil, fmt.Errorf("execute uniswap permit transaction: %w", err)
		}
		res.ApprovalRequired = true
		res.Permit = buildUniswapTradeExecutionResult(quoteResp.PermitTransaction, permitTxRes)
	}
	// 根据 Uniswap 返回的 routing 字段，决定是走 swap 方案还是 order 方案。
	// swap 方案是直接调用 Uniswap 的交换接口，order 方案是先创建订单，然后由 Uniswap 后台来执行交易。
	// swap 方案会更快一些，但 order 方案可能会有更好的价格或者更复杂的交易路径。
	switch {
	case uniswapRoutingUsesSwapEndpoint(res.Routing):
		permitDataForSwap := quoteResp.PermitData
		if isEmptyRawJSON(permitDataForSwap) {
			permitDataForSwap = nil
		}
		swapResp, err := fetchUniswapSwap(&UniswapTradeSwapRequest{
			Signature:  permitSignature,
			Quote:      quoteResp.Quote,
			PermitData: permitDataForSwap,
		})
		if err != nil {
			// 熔断机制
			if shouldFallbackToLifi(err) {
				return executeManagedUniswapSwapViaLifi(req, chain, from, tokenIn, tokenOut, amountIn, err)
			}
			return nil, err
		}
		res.RequestID = firstNonEmpty(res.RequestID, strings.TrimSpace(swapResp.RequestID))
		swapTxRes, err := executeUniswapTradeTx(req.UID, chain, from, tokenIn, swapResp.Swap)
		if err != nil {
			return nil, fmt.Errorf("execute uniswap swap: %w", err)
		}
		res.Swap = buildUniswapTradeExecutionResult(swapResp.Swap, swapTxRes)
	case uniswapRoutingUsesOrderEndpoint(res.Routing):
		intentTarget := uniswapFindFirstHexAddress(quoteResp.Quote, "reactor", "to")
		if intentTarget == "" {
			intentTarget = common.HexToAddress(evmPermit2Address).Hex()
		}
		tokenContract := ""
		if !isNativeIn {
			tokenContract = tokenIn
		}
		intent := &policy.Intent{
			Chain:         chain,
			SignMode:      "swap",
			To:            intentTarget,
			AmountWei:     amountIn.String(),
			TokenContract: tokenContract,
		}
		if err := validateUniswapProtocolTarget(chain, intentTarget); err != nil {
			return nil, err
		}
		if err := validateIntentWithRefreshForEvent(pe, intent, addrSnapshot, req.UID, "tx_swap_uniswap"); err != nil {
			return nil, err
		}

		orderResp, err := fetchUniswapOrder(&UniswapTradeOrderRequest{
			Signature: permitSignature,
			Quote:     quoteResp.Quote,
		})
		if err != nil {
			// 熔断机制
			if shouldFallbackToLifi(err) {
				return executeManagedUniswapSwapViaLifi(req, chain, from, tokenIn, tokenOut, amountIn, err)
			}
			return nil, err
		}
		pe.Commit(intent)
		res.RequestID = firstNonEmpty(res.RequestID, strings.TrimSpace(orderResp.RequestID))
		res.Order = orderResp
	default:
		return nil, fmt.Errorf("unsupported uniswap routing %q", res.Routing)
	}

	return res, nil
}

// solana jup
func handleJupiterSwap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JupiterSwapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedJupiterSwap(&req)
	if err != nil {
		audit.LogEvent("tx_swap_jupiter", req.UID, RuntimeSandboxLabel, "failed", err.Error())
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

	audit.LogEvent("tx_swap_jupiter", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s token_in=%s token_out=%s amt_in=%s", res.Chain, res.TokenIn, res.TokenOut, res.AmountInWei))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// sui cetus
func handleCetusSwap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CetusSwapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	res, err := executeManagedCetusSwap(&req)
	if err != nil {
		audit.LogEvent("tx_swap_cetus", req.UID, RuntimeSandboxLabel, "failed", err.Error())
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

	audit.LogEvent("tx_swap_cetus", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s token_in=%s token_out=%s amount=%s", res.Chain, res.TokenIn, res.TokenOut, res.AmountWei))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// cetus swap 逻辑
func executeManagedCetusSwap(req *CetusSwapRequest) (*CetusSwapResponse, error) {
	if req == nil {
		return nil, errors.New("missing swap request")
	}
	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		chain = "sui"
	}
	if chain != "sui" {
		return nil, fmt.Errorf("cetus swap is only supported on sui, got %q", req.Chain)
	}
	tokenIn := strings.TrimSpace(req.TokenIn)
	tokenOut := strings.TrimSpace(req.TokenOut)
	amountWei := strings.TrimSpace(req.AmountWei)
	if tokenIn == "" || tokenOut == "" || amountWei == "" {
		return nil, errors.New("token_in, token_out and amount_wei are required")
	}
	amount := new(big.Int)
	if _, ok := amount.SetString(amountWei, 10); !ok || amount.Sign() <= 0 {
		return nil, errors.New("amount_wei must be a positive integer string")
	}
	byAmountIn := true
	slippage := req.Slippage
	if slippage <= 0 {
		slippage = 0.005
	}
	if slippage > 0.5 {
		return nil, errors.New("slippage must be <= 0.5")
	}
	s, pe, snapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}
	from, err := utils.TransferFromAddress("sui", snapshot)
	if err != nil {
		return nil, err
	}
	wallet := from
	routeReq := &cetusFindRoutesRequest{From: tokenIn, Target: tokenOut, Amount: amount.String()}
	requestID, quoteAmountIn, quoteAmountOut, err := fetchCetusRoutes(defaultCetusFindRoutesURL, routeReq)
	if err != nil {
		return nil, err
	}
	txBytesBase64, err := fetchCetusSwapTxBytes(defaultCetusSwapV3URL, &cetusSwapBuildRequest{RequestID: requestID, Wallet: from, Slippage: slippage})
	if err != nil {
		return nil, err
	}
	if err := SuiDryRunTransactionBlock(txBytesBase64); err != nil {
		return nil, err
	}
	intent := &policy.Intent{
		Chain:         "sui",
		SignMode:      "swap",
		To:            from,
		AmountWei:     amount.String(),
		TokenContract: tokenIn,
	}
	if err := validateIntentWithRefreshForEvent(pe, intent, snapshot, req.UID, "tx_swap_cetus"); err != nil {
		return nil, err
	}
	// broadcastRes, err := BroadcastSignedTransaction(&BroadcastRequest{Chain: "sui", UID: req.UID, TxBytesBase64: txBytesBase64, Signature: serializedSignature, Options: json.RawMessage(`{"showEffects":true}`)})
	// if err != nil {
	// 	return nil, err
	// }
	builder := func(sponsorAddr string) (*BuildResult, error) {
		effectiveTxBytes := txBytesBase64
		if strings.TrimSpace(sponsorAddr) != "" {
			effectiveTxBytes, err = rebuildSuiSponsoredTxBytesFromRaw(context.Background(), txBytesBase64, from, sponsorAddr)
			if err != nil {
				return nil, err
			}
		}

		serializedSignature, err := signManagedSuiTransaction(s, effectiveTxBytes, &signer.SignRequest{
			UID:           strings.TrimSpace(req.UID),
			SignMode:      "swap",
			To:            intent.To,
			TokenContract: intent.TokenContract,
			AmountWei:     intent.AmountWei,
		})
		if err != nil {
			return nil, err
		}

		return &BuildResult{
			TxBase64:  effectiveTxBytes,
			Signature: serializedSignature,
		}, nil
	}

	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       "sui",
		FromAddress: from,
		UID:         req.UID,
	}, builder)
	if err != nil {
		return nil, err
	}
	pe.Commit(intent)
	//	return &CetusSwapResponse{Chain: "sui", From: from, Wallet: from, TokenIn: tokenIn, TokenOut: tokenOut, AmountWei: amount.String(), ByAmountIn: byAmountIn, Slippage: slippage, RequestID: requestID, QuoteAmountIn: quoteAmountIn, QuoteAmountOut: quoteAmountOut, TxBytesBase64: txBytesBase64, Digest: broadcastRes.Digest}, nil

	return &CetusSwapResponse{
		Chain:          "sui",
		From:           from,
		Wallet:         wallet,
		TokenIn:        tokenIn,
		TokenOut:       tokenOut,
		AmountWei:      amount.String(),
		ByAmountIn:     byAmountIn,
		Slippage:       slippage,
		RequestID:      requestID,
		QuoteAmountIn:  quoteAmountIn,
		QuoteAmountOut: quoteAmountOut,
		TxBytesBase64:  txBytesBase64,
		Digest:         broadcastRes.SubmittedID,
		Sponsored:      broadcastRes.Sponsored,
	}, nil
}

// jupiter swap 逻辑
func executeManagedJupiterSwap(req *JupiterSwapRequest) (*JupiterSwapResponse, error) {
	if req == nil {
		return nil, errors.New("missing swap request")
	}

	chain := strings.ToLower(strings.TrimSpace(req.Chain))
	if chain == "" {
		chain = "solana"
	}
	if chain != "solana" {
		return nil, fmt.Errorf("jupiter swap is only supported on solana, got %q", req.Chain)
	}

	tokenInRaw := strings.TrimSpace(req.TokenIn)
	tokenOutRaw := strings.TrimSpace(req.TokenOut)
	amountInRaw := strings.TrimSpace(req.AmountInWei)

	if tokenOutRaw == "" || amountInRaw == "" {
		return nil, errors.New("token_out and amount_in_wei are required")
	}

	amountIn := new(big.Int)
	if _, ok := amountIn.SetString(amountInRaw, 10); !ok || amountIn.Sign() <= 0 {
		return nil, errors.New("amount_in_wei must be a positive integer string")
	}
	if !amountIn.IsUint64() {
		return nil, errors.New("solana amount_in_wei exceeds uint64 range")
	}

	slippageBps := req.SlippageBps
	if slippageBps == 0 {
		slippageBps = 50
	}

	isNativeIn := tokenInRaw == "" || strings.EqualFold(tokenInRaw, "native")
	isNativeOut := strings.EqualFold(tokenOutRaw, "native")

	inputMint, err := resolveSolanaMint(tokenInRaw)
	if err != nil {
		return nil, fmt.Errorf("resolve token_in mint: %w", err)
	}
	outputMint, err := resolveSolanaMint(tokenOutRaw)
	if err != nil {
		return nil, fmt.Errorf("resolve token_out mint: %w", err)
	}

	s, pe, addrSnapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	from, err := utils.TransferFromAddress(chain, addrSnapshot)
	if err != nil {
		return nil, err
	}
	quoteRaw, quoteParsed, err := fetchJupiterQuote(defaultJupiterQuoteURL, inputMint, outputMint, amountIn.Uint64(), slippageBps, req.AsLegacyTransaction)
	if err != nil {
		return nil, err
	}

	wrapAndUnwrapSol := true
	if req.WrapAndUnwrapSol != nil {
		wrapAndUnwrapSol = *req.WrapAndUnwrapSol
	}
	useSharedAccounts := true
	if req.UseSharedAccounts != nil {
		useSharedAccounts = *req.UseSharedAccounts
	}
	dynamicComputeUnitLimit := true
	if req.DynamicComputeUnitLimit != nil {
		dynamicComputeUnitLimit = *req.DynamicComputeUnitLimit
	}

	swapTxBase64, lastValidBlockHeight, err := fetchJupiterSwapTx(defaultJupiterSwapURL, from, quoteRaw, wrapAndUnwrapSol, useSharedAccounts, dynamicComputeUnitLimit, req.AsLegacyTransaction)
	if err != nil {
		return nil, err
	}

	txBytes, err := base64.StdEncoding.DecodeString(swapTxBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid swapTransaction base64: %w", err)
	}

	meta, messageBytes, err := solanaExtractMessageMeta(txBytes)
	if err != nil {
		return nil, err
	}
	if meta.Payer != from {
		return nil, fmt.Errorf("swap transaction payer mismatch: got %s want %s", meta.Payer, from)
	}
	if meta.RequiredSignatures != 1 || len(meta.Signers) != 1 || meta.Signers[0] != from {
		return nil, fmt.Errorf("unexpected signer set: required=%d signers=%v", meta.RequiredSignatures, meta.Signers)
	}
	jupProgram, err := validateJupiterPrograms(meta.ProgramIDs)
	if err != nil {
		return nil, err
	}

	tokenContract := inputMint
	if isNativeIn {
		tokenContract = ""
	}
	intent := &policy.Intent{
		Chain:         chain,
		SignMode:      "swap",
		To:            jupProgram,
		AmountWei:     amountIn.String(),
		TokenContract: tokenContract,
	}
	if err := validateIntentWithRefreshForEvent(pe, intent, addrSnapshot, req.UID, "tx_swap_jupiter"); err != nil {
		return nil, err
	}

	var finalSignedBase64 string
	var finalSignature string
	builder := func(sponsorAddr string) (*BuildResult, error) {
		effectiveTxBytes := txBytes
		effectiveMessageBytes := messageBytes
		if strings.TrimSpace(sponsorAddr) != "" {
			effectiveMessageBytes, err = solanaRebuildMessageWithSponsorPayer(messageBytes, from, sponsorAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to rebuild jupiter swap message with sponsor payer: %w", err)
			}
			effectiveTxBytes, err = solanaBuildUnsignedTxBytesFromMessage(effectiveMessageBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to build jupiter swap tx bytes from sponsored message: %w", err)
			}
		}

		signedBytes, serializedSignature, err := solanaSignAndAttachSignatureByAddress(s, effectiveTxBytes, effectiveMessageBytes, from)
		if err != nil {
			return nil, fmt.Errorf("failed to sign jupiter swap: %w", err)
		}
		finalSignedBase64 = base64.StdEncoding.EncodeToString(signedBytes)
		finalSignature = serializedSignature
		userSignatureBase58, err := extractSolanaSignatureBase58ByAddressFromRawTxBase64(finalSignedBase64, from)
		if err != nil {
			return nil, err
		}
		return &BuildResult{
			TxBase64: finalSignedBase64,
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
	policyEngine.Commit(intent)

	outTokenIn := tokenInRaw
	if isNativeIn {
		outTokenIn = "native"
	} else {
		outTokenIn = inputMint
	}
	outTokenOut := tokenOutRaw
	if isNativeOut {
		outTokenOut = "native"
	} else {
		outTokenOut = outputMint
	}

	return &JupiterSwapResponse{
		Chain:                "solana",
		From:                 from,
		TokenIn:              outTokenIn,
		TokenOut:             outTokenOut,
		AmountInWei:          amountIn.String(),
		SlippageBps:          slippageBps,
		InAmount:             quoteParsed.InAmount,
		OutAmount:            quoteParsed.OutAmount,
		OtherAmountThreshold: quoteParsed.OtherAmountThreshold,
		SwapMode:             quoteParsed.SwapMode,
		AsLegacyTransaction:  req.AsLegacyTransaction,
		UsedVersionedTx:      meta.Versioned,
		JupiterProgram:       jupProgram,
		SwapTxBase64:         finalSignedBase64,
		MessageHex:           "0x" + hex.EncodeToString(messageBytes),
		SubmittedID:          broadcastRes.SubmittedID,
		Signature:            finalSignature,
		LastValidBlockHeight: lastValidBlockHeight,
		Sponsored:            broadcastRes.Sponsored,
	}, nil
}

// ========⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️================
// EVM uniswap 相关
func uniswapChainID(chain string) (int, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	chainID, ok := uniswapChainIDByChain[chain]
	if !ok {
		return 0, fmt.Errorf("uniswap api is not configured for chain %q", chain)
	}
	return chainID, nil
}

func normalizeUniswapTokenAddress(chain, raw string, allowNative bool) (string, bool, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	token := strings.TrimSpace(raw)
	if token == "" || strings.EqualFold(token, "native") {
		if !allowNative {
			return "", false, errors.New("token address is required")
		}
		return common.HexToAddress(evmNativeTokenAddress).Hex(), true, nil
	}
	if resolved := lookupCommonEVMTokenAddress(chain, token); resolved != "" {
		return resolved, false, nil
	}
	if !common.IsHexAddress(token) {
		return "", false, fmt.Errorf("token must be a contract address or a supported symbol; token_in and token_out need address when symbol is not built-in (got %q)", raw)
	}
	return common.HexToAddress(token).Hex(), false, nil
}

func lookupCommonEVMTokenAddress(chain, token string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	symbol := strings.ToUpper(strings.TrimSpace(token))
	if symbol == "" {
		return ""
	}
	if symbol == "NATIVE" {
		return ""
	}
	if m, ok := evmCommonTokenByChain[chain]; ok {
		if addr := strings.TrimSpace(m[symbol]); common.IsHexAddress(addr) {
			return common.HexToAddress(addr).Hex()
		}
	}
	return ""
}

func uniswapTradeAPITimeout() time.Duration {
	if raw := strings.TrimSpace(env("UNISWAP_TRADE_API_TIMEOUT_MS", "35000")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 35 * time.Second
}

func lifiChainIDForChain(chain string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum":
		return "1", nil
	case "optimism":
		return "10", nil
	case "bsc":
		return "56", nil
	case "polygon":
		return "137", nil
	case "monad":
		return "143", nil
	case "zksync":
		return "324", nil
	case "arbitrum":
		return "42161", nil
	case "avalanche":
		return "43114", nil
	case "base":
		return "8453", nil
	case "linea":
		return "59144", nil
	default:
		return "", fmt.Errorf("li.fi fallback is not configured for chain %q", chain)
	}
}

func normalizeUniswapProtocols(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		norm := strings.ToUpper(strings.TrimSpace(item))
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

func normalizeUniswapAutoSlippage(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "":
		return "DEFAULT"
	case "DEFAULT", "AUTO":
		return "DEFAULT"
	default:
		return strings.TrimSpace(raw)
	}
}

func normalizeUniswapPermitAmount(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "FULL":
		return "FULL"
	default:
		return strings.TrimSpace(raw)
	}
}

func fetchUniswapApproval(body *UniswapTradeApprovalRequest) (*UniswapTradeApprovalResponse, error) {
	if body == nil {
		return nil, errors.New("missing uniswap approval request")
	}
	var out UniswapTradeApprovalResponse
	if err := postUniswapTradeAPI("/check_approval", body, &out); err != nil {
		return nil, fmt.Errorf("uniswap approval request failed: %w", err)
	}
	return &out, nil
}

func fetchUniswapQuote(body *UniswapTradeQuoteRequest) (*UniswapTradeQuoteResponse, error) {
	if body == nil {
		return nil, errors.New("missing uniswap quote request")
	}
	var out UniswapTradeQuoteResponse
	if err := postUniswapTradeAPI("/quote", body, &out); err != nil {
		return nil, fmt.Errorf("uniswap quote request failed: %w", err)
	}
	if len(out.Quote) == 0 {
		return nil, &uniswapTradeAPICallError{
			path:      "/quote",
			retryable: true,
			err:       errors.New("uniswap quote response missing quote"),
		}
	}
	if strings.TrimSpace(out.Routing) == "" {
		return nil, &uniswapTradeAPICallError{
			path:      "/quote",
			retryable: true,
			err:       errors.New("uniswap quote response missing routing"),
		}
	}
	if isEmptyRawJSON(out.PermitData) {
		out.PermitData = nil
	}
	return &out, nil
}

func fetchUniswapSwap(body *UniswapTradeSwapRequest) (*UniswapTradeSwapResponse, error) {
	if body == nil {
		return nil, errors.New("missing uniswap swap request")
	}
	simulate := false
	body.SimulateTransaction = &simulate
	var out UniswapTradeSwapResponse
	if err := postUniswapTradeAPI("/swap", body, &out); err != nil {
		return nil, fmt.Errorf("uniswap swap request failed: %w", err)
	}
	if out.Swap == nil {
		return nil, &uniswapTradeAPICallError{
			path:      "/swap",
			retryable: true,
			err:       errors.New("uniswap swap response missing swap transaction"),
		}
	}
	return &out, nil
}

func fetchUniswapOrder(body *UniswapTradeOrderRequest) (*UniswapTradeOrderResponse, error) {
	if body == nil {
		return nil, errors.New("missing uniswap order request")
	}
	var out UniswapTradeOrderResponse
	if err := postUniswapTradeAPI("/order", body, &out); err != nil {
		return nil, fmt.Errorf("uniswap order request failed: %w", err)
	}
	if strings.TrimSpace(out.OrderID) == "" && strings.TrimSpace(out.RequestID) == "" {
		return nil, &uniswapTradeAPICallError{
			path:      "/order",
			retryable: true,
			err:       errors.New("uniswap order response missing request id"),
		}
	}
	return &out, nil
}

// 判定是否应该从 Uniswap API 熔断到 LIFI 的核心逻辑是根据错误类型和内容来判断的。
// 如果 Uniswap API 返回的是网络错误、超时错误或者 5xx 的服务器错误，这些都是可能是暂时性的，适合进行熔断并尝试使用 LIFI 作为备用方案。
// 而如果错误是由于请求参数问题（比如缺少必填字段、参数格式错误等）导致的，那么这些通常不是暂时性的，熔断到 LIFI 可能也无法成功，这种情况下就不建议进行熔断。
func shouldFallbackToLifi(err error) bool {
	var apiErr *uniswapTradeAPICallError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr != nil && apiErr.retryable
}

func executeManagedUniswapSwapViaLifi(req *UniswapSwapTradeAPIRequest, chain, from, tokenIn, tokenOut string, amountIn *big.Int, cause error) (*UniswapSwapTradeAPIResponse, error) {
	chainID, err := lifiChainIDForChain(chain)
	if err != nil {
		return nil, fmt.Errorf("uniswap api failed and li.fi fallback is unavailable: %w", cause)
	}
	identityUID := strings.TrimSpace(boundUid)
	if identityUID == "" {
		return nil, fmt.Errorf("uniswap api failed (%v) and li.fi fallback is unavailable: wallet uid is not bound", cause)
	}
	taskUID := uuid.NewString()
	// 当前同链swap from和 to 都是用户地址，li.fi 会帮忙处理跨协议的桥接和交换逻辑
	lifiReq := &LifiBridgeRequest{
		FromChainID: chainID,
		FromAddress: from,
		FromToken:   tokenIn,
		Amount:      amountIn.String(),
		ToChainID:   chainID,
		ToAddress:   from,
		ToToken:     tokenOut,
		Slippage:    uniswapRequestSlippageForLifi(req),
	}
	lifiRes, err := executeManagedLifiSameChainSwap(lifiReq, identityUID, taskUID)
	if err != nil {
		return nil, fmt.Errorf("uniswap api failed (%v) and li.fi fallback failed: %w", cause, err)
	}
	if !lifiRes.Success {
		msg := strings.TrimSpace(lifiRes.Message)
		if msg == "" {
			msg = "li.fi fallback failed"
		}
		return nil, fmt.Errorf("uniswap api failed (%v) and li.fi fallback returned failure: %s", cause, msg)
	}
	return &UniswapSwapTradeAPIResponse{
		Chain:       chain,
		From:        from,
		RequestID:   "lifi-fallback",
		Routing:     "LIFI_FALLBACK",
		TokenIn:     tokenIn,
		TokenOut:    tokenOut,
		AmountInWei: amountIn.String(),
		Swap: &UniswapTradeExecutionResult{
			SubmittedID: strings.TrimSpace(lifiRes.FinalTxHash),
			TxHash:      strings.TrimSpace(lifiRes.FinalTxHash),
		},
	}, nil
}

func uniswapRequestSlippageForLifi(req *UniswapSwapTradeAPIRequest) float64 {
	if req == nil {
		return 0.005
	}
	if req.SlippageTolerance > 0 {
		return float64(req.SlippageTolerance) / 10000.0
	}
	return 0.005
}

// uniswap API 的请求和响应处理逻辑，包括构造 HTTP 请求、处理响应、错误分类等。
func postUniswapTradeAPI(path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	tradeApiUrl := strings.TrimRight(strings.TrimSpace(defaultUniswapTradeAPIURL), "/")
	timeout := uniswapTradeAPITimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tradeApiUrl+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-universal-router-version", "2.0")
	if apiKey := uniswapAPIKey(); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return classifyUniswapTradeAPIRequestError(path, timeout, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500
		return &uniswapTradeAPICallError{
			path:      path,
			retryable: retryable,
			err:       fmt.Errorf("http %d: %s", resp.StatusCode, uniswapTradeAPIError(raw)),
		}
	}
	if len(raw) == 0 {
		return &uniswapTradeAPICallError{
			path:      path,
			retryable: true,
			err:       errors.New("empty uniswap response"),
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &uniswapTradeAPICallError{
			path:      path,
			retryable: true,
			err:       fmt.Errorf("failed to decode uniswap response: %w", err),
		}
	}
	return nil
}

func classifyUniswapTradeAPIRequestError(path string, timeout time.Duration, err error) error {
	label := strings.TrimPrefix(strings.TrimSpace(path), "/")
	if label == "" {
		label = "request"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &uniswapTradeAPICallError{
			path:      path,
			retryable: true,
			err:       fmt.Errorf("uniswap %s request timed out after %s; trade api may be slow or temporarily unreachable", label, timeout.Round(time.Second)),
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &uniswapTradeAPICallError{
			path:      path,
			retryable: true,
			err:       fmt.Errorf("uniswap %s request timed out after %s; trade api may be slow or temporarily unreachable", label, timeout.Round(time.Second)),
		}
	}
	return &uniswapTradeAPICallError{
		path:      path,
		retryable: true,
		err:       err,
	}
}

func uniswapTradeAPIError(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "empty error response"
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return trimmed
	}
	parts := []string{}
	for _, key := range []string{"detail", "message", "error", "errorCode", "reason"} {
		if val := anyToTrimmedString(payload[key]); val != "" {
			parts = append(parts, val)
		}
	}
	if len(parts) == 0 {
		return trimmed
	}
	return strings.Join(parts, " | ")
}

func validateUniswapTradeTxTarget(chain, tokenIn, to, data string) error {
	if isERC20ApproveCalldata(data) {
		if !common.IsHexAddress(tokenIn) || common.HexToAddress(tokenIn).Hex() != common.HexToAddress(to).Hex() {
			return fmt.Errorf("uniswap approval tx target mismatch: got %s want token contract %s", to, tokenIn)
		}
		spender, err := extractERC20ApproveSpender(data)
		if err != nil {
			return err
		}
		return validateUniswapProtocolTarget(chain, spender)
	}
	return validateUniswapProtocolTarget(chain, to)
}

func validateUniswapProtocolTarget(chain, target string) error {
	target = strings.TrimSpace(target)
	if !common.IsHexAddress(target) {
		return fmt.Errorf("invalid uniswap protocol target %q", target)
	}
	if common.HexToAddress(target).Hex() == common.HexToAddress(evmPermit2Address).Hex() || isEVMUniversalRouter(chain, target) {
		return nil
	}
	return fmt.Errorf("uniswap target %s is not in the built-in protocol allowlist for %s", common.HexToAddress(target).Hex(), chain)
}

func isERC20ApproveCalldata(data string) bool {
	data = strings.ToLower(strings.TrimSpace(data))
	return strings.HasPrefix(data, "0x095ea7b3") && len(data) >= 138
}

func extractERC20ApproveSpender(data string) (string, error) {
	data = strings.TrimSpace(data)
	if !isERC20ApproveCalldata(data) {
		return "", errors.New("not an ERC20 approve calldata payload")
	}
	spenderHex := "0x" + data[34:74]
	if !common.IsHexAddress(spenderHex) {
		return "", fmt.Errorf("invalid approve spender %q", spenderHex)
	}
	return common.HexToAddress(spenderHex).Hex(), nil
}

func executeUniswapTradeTx(uid, chain, from, tokenIn string, tx *UniswapTradeTx) (*ManagedEVMTxResponse, error) {
	if tx == nil {
		return nil, errors.New("missing uniswap transaction")
	}
	to := strings.TrimSpace(tx.To)
	if !common.IsHexAddress(to) {
		return nil, fmt.Errorf("invalid uniswap tx to address %q", tx.To)
	}
	if tx.ChainID != 0 {
		wantChainID, err := uniswapChainID(chain)
		if err != nil {
			return nil, err
		}
		if tx.ChainID != wantChainID {
			return nil, fmt.Errorf("uniswap tx chain id mismatch: got %d want %d", tx.ChainID, wantChainID)
		}
	}
	if txFrom := strings.TrimSpace(tx.From); txFrom != "" && common.IsHexAddress(txFrom) {
		if common.HexToAddress(txFrom).Hex() != common.HexToAddress(from).Hex() {
			return nil, fmt.Errorf("uniswap tx from mismatch: got %s want %s", txFrom, from)
		}
	}
	value, err := normalizeUniswapTxValue(tx.Value)
	if err != nil {
		return nil, err
	}
	data := strings.TrimSpace(tx.Data)
	if data == "" {
		data = "0x"
	}
	if err := validateUniswapTradeTxTarget(chain, tokenIn, common.HexToAddress(to).Hex(), data); err != nil {
		return nil, err
	}
	return executeManagedEVMInvokeEIP1559(&ManagedEVMInvokeRequest{
		UID:             strings.TrimSpace(uid),
		Chain:           chain,
		SignMode:        "swap",
		To:              common.HexToAddress(to).Hex(),
		Value:           value,
		Data:            data,
		ConfirmedByUser: true,
	})
}

func buildUniswapTradeExecutionResult(tx *UniswapTradeTx, res *ManagedEVMTxResponse) *UniswapTradeExecutionResult {
	if tx == nil && res == nil {
		return nil
	}
	out := &UniswapTradeExecutionResult{
		Tx: tx,
	}
	if res != nil {
		out.SubmittedID = strings.TrimSpace(res.SubmittedID)
		out.TxHash = strings.TrimSpace(res.TxHash)
	}
	return out
}

func normalizeUniswapTxValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "0", nil
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		out, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			return "", fmt.Errorf("invalid hex tx value %q", raw)
		}
		return out.String(), nil
	}
	out, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return "", fmt.Errorf("invalid tx value %q", raw)
	}
	return out.String(), nil
}

func signUniswapPermitData(s *signer.Signer, chain, uid string, permitData json.RawMessage) (string, error) {
	if s == nil {
		return "", errors.New("missing signer")
	}
	if isEmptyRawJSON(permitData) {
		return "", nil
	}
	signReq := signer.SignRequest{
		Chain:     chain,
		SignMode:  "typed_data",
		UID:       strings.TrimSpace(uid),
		TypedData: permitData,
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return "", err
	}
	signRes, err := s.Sign(&signReq)
	if err != nil {
		return "", fmt.Errorf("failed to sign uniswap permit data: %w", err)
	}
	return signRes.SignatureHex, nil
}

func isEmptyRawJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func extractUniswapQuoteOutputAmount(raw json.RawMessage) string {
	if isEmptyRawJSON(raw) {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	if outputs, ok := payload["aggregatedOutputs"].([]any); ok {
		for _, item := range outputs {
			if output, ok := item.(map[string]any); ok {
				for _, key := range []string{"minAmount", "amount", "amountOut"} {
					if val := anyToTrimmedString(output[key]); val != "" {
						return val
					}
				}
			}
		}
	}
	if output, ok := payload["output"].(map[string]any); ok {
		for _, key := range []string{"minAmount", "amount", "amountOut"} {
			if val := anyToTrimmedString(output[key]); val != "" {
				return val
			}
		}
	}
	return uniswapFindString(raw, "minAmount", "amountOut", "outAmount")
}

func uniswapFindString(raw json.RawMessage, keys ...string) string {
	if isEmptyRawJSON(raw) {
		return ""
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	keySet := map[string]struct{}{}
	for _, key := range keys {
		keySet[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}

	var walk func(any) string
	walk = func(cur any) string {
		switch v := cur.(type) {
		case map[string]any:
			for key, val := range v {
				if _, ok := keySet[strings.ToLower(strings.TrimSpace(key))]; ok {
					if out := anyToTrimmedString(val); out != "" {
						return out
					}
				}
			}
			for _, val := range v {
				if out := walk(val); out != "" {
					return out
				}
			}
		case []any:
			for _, val := range v {
				if out := walk(val); out != "" {
					return out
				}
			}
		}
		return ""
	}

	return walk(payload)
}

func uniswapFindFirstHexAddress(raw json.RawMessage, keys ...string) string {
	if candidate := uniswapFindString(raw, keys...); common.IsHexAddress(candidate) {
		return common.HexToAddress(candidate).Hex()
	}
	return ""
}

func anyToTrimmedString(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case json.Number:
		return strings.TrimSpace(val.String())
	case float64:
		return strings.TrimSpace(strconv.FormatInt(int64(val), 10))
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	default:
		return ""
	}
}

func uniswapRoutingUsesSwapEndpoint(routing string) bool {
	switch strings.ToUpper(strings.TrimSpace(routing)) {
	case "CLASSIC", "WRAP", "UNWRAP", "BRIDGE":
		return true
	default:
		return false
	}
}

func uniswapRoutingUsesOrderEndpoint(routing string) bool {
	switch strings.ToUpper(strings.TrimSpace(routing)) {
	case "DUTCH_V2", "DUTCH_V3", "PRIORITY", "DUTCH_LIMIT", "LIMIT_ORDER":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// 后期熔断方案伪代码:
// 1. 仅在 Trade API 超时、5xx、429 或返回结构异常时触发。
// 2. 从 evmUniversalRouterByChain 里选择主/备 Universal Router，不在这里做链路可达性探测。
// 3. 本地构建 Permit2 approve + Universal Router execute calldata，并用 eth_call 做最小化预检。
// 4. 若主路由构建/模拟失败，再切换备路由；成功率稳定后再决定是否正式接入自动熔断。

// ========⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️================
// jupiter swap 相关逻辑，包含一些针对 solana 的特殊处理
func normalizeSolanaMint(mint string) string {
	mint = strings.TrimSpace(mint)
	if mint == "" || strings.EqualFold(mint, "native") {
		return solanaWSOLMint
	}
	return mint
}

// SOL上需要token-address
type jupiterSearchToken struct {
	Address string `json:"address"`
	Symbol  string `json:"symbol"`
	Name    string `json:"name,omitempty"`
}

func resolveSolanaMint(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" || strings.EqualFold(token, "native") {
		return solanaWSOLMint, nil
	}
	if isValidSolanaMintAddress(token) {
		return token, nil
	}
	if builtin := lookupCommonSolanaMint(token); builtin != "" {
		return builtin, nil
	}
	mint, err := fetchJupiterTokenMint(defaultJupiterTokenSearchURL, token)
	if err != nil {
		return "", err
	}
	return mint, nil
}

func lookupCommonSolanaMint(token string) string {
	token = strings.ToUpper(strings.TrimSpace(token))
	if token == "" {
		return ""
	}
	return solanaCommonTokenMints[token]
}

func isValidSolanaMintAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	_, err := solanago.PublicKeyFromBase58(value)
	return err == nil
}

func fetchJupiterTokenMint(searchURL, symbol string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(searchURL))
	if err != nil {
		return "", fmt.Errorf("invalid jupiter token search url: %w", err)
	}
	symbol = strings.TrimSpace(symbol)
	if symbol == "" {
		return "", errors.New("empty token symbol")
	}
	q := u.Query()
	q.Set("query", symbol)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if apiKey := jupiterAPIKey(); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", fmt.Errorf("jupiter token search request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("jupiter token search http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var tokens []jupiterSearchToken
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return "", fmt.Errorf("failed to decode jupiter token search response: %w", err)
	}
	for _, token := range tokens {
		if !strings.EqualFold(strings.TrimSpace(token.Symbol), symbol) {
			continue
		}
		address := strings.TrimSpace(token.Address)
		if isValidSolanaMintAddress(address) {
			return address, nil
		}
	}
	return "", fmt.Errorf("jupiter token search returned no exact symbol match for %q", symbol)
}

func fetchJupiterQuote(quoteURL, inputMint, outputMint string, amount uint64, slippageBps uint16, asLegacy bool) (json.RawMessage, *jupiterQuoteResponse, error) {
	u, err := url.Parse(strings.TrimSpace(quoteURL))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid jupiter quote url: %w", err)
	}
	q := u.Query()
	q.Set("inputMint", inputMint)
	q.Set("outputMint", outputMint)
	q.Set("amount", strconv.FormatUint(amount, 10))
	q.Set("slippageBps", strconv.Itoa(int(slippageBps)))
	q.Set("swapMode", "ExactIn")
	if asLegacy {
		q.Set("asLegacyTransaction", "true")
	}
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	if apiKey := jupiterAPIKey(); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("jupiter quote request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("jupiter quote http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed jupiterQuoteResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to decode jupiter quote response: %w", err)
	}
	if !strings.EqualFold(parsed.InputMint, inputMint) || !strings.EqualFold(parsed.OutputMint, outputMint) {
		return nil, nil, errors.New("jupiter quote mint mismatch")
	}
	if strings.TrimSpace(parsed.InAmount) == "" || strings.TrimSpace(parsed.OutAmount) == "" {
		return nil, nil, errors.New("jupiter quote missing inAmount/outAmount")
	}

	return json.RawMessage(raw), &parsed, nil
}

func fetchJupiterSwapTx(swapURL, userPublicKey string, quoteRaw json.RawMessage, wrapAndUnwrapSol, useSharedAccounts, dynamicComputeUnitLimit, asLegacy bool) (string, uint64, error) {
	body := jupiterSwapBody{
		UserPublicKey:           userPublicKey,
		QuoteResponse:           quoteRaw,
		WrapAndUnwrapSol:        wrapAndUnwrapSol,
		UseSharedAccounts:       useSharedAccounts,
		DynamicComputeUnitLimit: dynamicComputeUnitLimit,
		AsLegacyTransaction:     asLegacy,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(swapURL), bytes.NewReader(payload))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := jupiterAPIKey(); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("jupiter swap request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", 0, fmt.Errorf("jupiter swap http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed jupiterSwapResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", 0, fmt.Errorf("failed to decode jupiter swap response: %w", err)
	}
	if strings.TrimSpace(parsed.SwapTransaction) == "" {
		return "", 0, errors.New("jupiter swap response missing swapTransaction")
	}
	return parsed.SwapTransaction, parsed.LastValidBlockHeight, nil
}

func fetchCetusRoutes(findURL string, req *cetusFindRoutesRequest) (string, string, string, error) {
	if req == nil {
		return "", "", "", errors.New("missing cetus route request")
	}
	u, err := url.Parse(strings.TrimSpace(findURL))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid cetus find_routes url: %w", err)
	}
	q := u.Query()
	q.Set("from", req.From)
	q.Set("target", req.Target)
	q.Set("amount", req.Amount)
	q.Set("by_amount_in", "true")
	q.Set("v", "1999999")
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", "", err
	}
	resp, err := (&http.Client{}).Do(httpReq)
	if err != nil {
		return "", "", "", fmt.Errorf("cetus find_routes request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", "", "", fmt.Errorf("cetus find_routes http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return parseCetusRoutesPayload(raw)
}

func validateCetusAPIEndpoint(rawURL string) error {
	host := mustURLHost(rawURL)
	if host == "" {
		return fmt.Errorf("invalid cetus api url %q", rawURL)
	}
	if _, ok := cetusAllowedAPIHosts[host]; ok {
		return nil
	}
	return fmt.Errorf("cetus api host %q is not in the built-in allowlist", host)
}

func mustURLHost(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

func solanaExtractMessageMeta(txBytes []byte) (*solanaMessageMeta, []byte, error) {
	if len(txBytes) == 0 {
		return nil, nil, errors.New("empty solana transaction bytes")
	}

	sigCount, n, err := solanaDecodeShortVec(txBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature count: %w", err)
	}
	if sigCount == 0 {
		return nil, nil, errors.New("solana transaction has zero signatures")
	}
	sigSection := n + int(sigCount)*64
	if sigSection > len(txBytes) {
		return nil, nil, errors.New("solana transaction truncated at signatures section")
	}

	message := txBytes[sigSection:]
	meta, err := solanaParseMessageMeta(message)
	if err != nil {
		return nil, nil, err
	}
	if uint64(meta.RequiredSignatures) != sigCount {
		return nil, nil, fmt.Errorf("signature count mismatch: tx=%d message=%d", sigCount, meta.RequiredSignatures)
	}
	return meta, message, nil
}

func solanaBuildUnsignedTxBytesFromMessage(messageBytes []byte) ([]byte, error) {
	meta, err := solanaParseMessageMeta(messageBytes)
	if err != nil {
		return nil, err
	}
	if meta.RequiredSignatures == 0 {
		return nil, errors.New("solana message requires zero signatures")
	}
	prefix := solanaEncodeShortVec(uint64(meta.RequiredSignatures))
	out := make([]byte, 0, len(prefix)+int(meta.RequiredSignatures)*64+len(messageBytes))
	out = append(out, prefix...)
	out = append(out, make([]byte, int(meta.RequiredSignatures)*64)...)
	out = append(out, messageBytes...)
	return out, nil
}

func solanaRebuildMessageWithSponsorPayer(messageBytes []byte, fromAddr, sponsorAddr string) ([]byte, error) {
	fromAddr = strings.TrimSpace(fromAddr)
	sponsorAddr = strings.TrimSpace(sponsorAddr)
	if fromAddr == "" || sponsorAddr == "" {
		return nil, errors.New("missing solana from/sponsor address")
	}
	if fromAddr == sponsorAddr {
		return nil, errors.New("solana sponsor address must be different from from address")
	}
	if len(messageBytes) < 4 {
		return nil, errors.New("solana message too short")
	}
	if messageBytes[0]&0x80 != 0 {
		return nil, errors.New("sponsor payer rewrite only supports legacy solana messages")
	}
	required := int(messageBytes[0])
	readonlySigned := int(messageBytes[1])
	readonlyUnsigned := int(messageBytes[2])
	if required != 1 || readonlySigned != 0 {
		return nil, errors.New("sponsor payer rewrite requires single writable signer message")
	}
	i := 3
	keyCountU64, n, err := solanaDecodeShortVec(messageBytes[i:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode account keys length: %w", err)
	}
	i += n
	keyCount := int(keyCountU64)
	if keyCount <= 0 {
		return nil, errors.New("solana message has zero account keys")
	}
	if i+keyCount*32 > len(messageBytes) {
		return nil, errors.New("solana message truncated at account keys")
	}
	keys := make([][]byte, keyCount)
	for k := 0; k < keyCount; k++ {
		key := make([]byte, 32)
		copy(key, messageBytes[i:i+32])
		i += 32
		keys[k] = key
	}
	fromPub, err := solanago.PublicKeyFromBase58(fromAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid solana from address: %w", err)
	}
	if !bytes.Equal(keys[0], fromPub[:]) {
		return nil, errors.New("solana message payer mismatch with from address")
	}
	sponsorPub, err := solanago.PublicKeyFromBase58(sponsorAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid solana sponsor address: %w", err)
	}
	if i+32 > len(messageBytes) {
		return nil, errors.New("solana message missing recent blockhash")
	}
	recent := make([]byte, 32)
	copy(recent, messageBytes[i:i+32])
	i += 32
	ixCountU64, n, err := solanaDecodeShortVec(messageBytes[i:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode instruction count: %w", err)
	}
	i += n
	type ins struct {
		program byte
		accs    []byte
		data    []byte
	}
	instructions := make([]ins, 0, int(ixCountU64))
	for ix := 0; ix < int(ixCountU64); ix++ {
		if i >= len(messageBytes) {
			return nil, errors.New("solana message truncated at instruction")
		}
		program := messageBytes[i]
		i++
		accLenU64, n, err := solanaDecodeShortVec(messageBytes[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode instruction accounts length: %w", err)
		}
		i += n
		accLen := int(accLenU64)
		if i+accLen > len(messageBytes) {
			return nil, errors.New("solana message truncated at instruction accounts")
		}
		accs := make([]byte, accLen)
		copy(accs, messageBytes[i:i+accLen])
		i += accLen
		dataLenU64, n, err := solanaDecodeShortVec(messageBytes[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode instruction data length: %w", err)
		}
		i += n
		dataLen := int(dataLenU64)
		if i+dataLen > len(messageBytes) {
			return nil, errors.New("solana message truncated at instruction data")
		}
		data := make([]byte, dataLen)
		copy(data, messageBytes[i:i+dataLen])
		i += dataLen
		instructions = append(instructions, ins{program: program, accs: accs, data: data})
	}
	if i != len(messageBytes) {
		return nil, errors.New("sponsor payer rewrite does not support address table lookups")
	}
	sponsorIdx := -1
	for idx := 1; idx < len(keys); idx++ {
		if bytes.Equal(keys[idx], sponsorPub[:]) {
			sponsorIdx = idx
			break
		}
	}
	newReadonlyUnsigned := readonlyUnsigned
	if sponsorIdx >= 1 && sponsorIdx >= keyCount-readonlyUnsigned {
		newReadonlyUnsigned--
	}
	newKeys := make([][]byte, 0, keyCount+1)
	newKeys = append(newKeys, sponsorPub[:])
	for idx, key := range keys {
		if idx == sponsorIdx {
			continue
		}
		newKeys = append(newKeys, key)
	}
	if len(newKeys) > 255 {
		return nil, errors.New("solana message account keys exceed uint8 range")
	}
	remap := make([]byte, keyCount)
	for idx := 0; idx < keyCount; idx++ {
		if idx == sponsorIdx {
			remap[idx] = 0
			continue
		}
		if sponsorIdx == -1 || idx < sponsorIdx {
			remap[idx] = byte(idx + 1)
		} else {
			remap[idx] = byte(idx)
		}
	}
	for ix := range instructions {
		oldProgram := int(instructions[ix].program)
		if oldProgram < 0 || oldProgram >= keyCount {
			return nil, errors.New("solana instruction program index out of range")
		}
		instructions[ix].program = remap[oldProgram]
		for j := range instructions[ix].accs {
			oldAcc := int(instructions[ix].accs[j])
			if oldAcc < 0 || oldAcc >= keyCount {
				return nil, errors.New("solana instruction account index out of range")
			}
			instructions[ix].accs[j] = remap[oldAcc]
		}
	}
	out := make([]byte, 0, len(messageBytes)+64)
	out = append(out, 0x02, 0x00, byte(newReadonlyUnsigned))
	out = append(out, solanaEncodeShortVec(uint64(len(newKeys)))...)
	for _, key := range newKeys {
		out = append(out, key...)
	}
	out = append(out, recent...)
	out = append(out, solanaEncodeShortVec(uint64(len(instructions)))...)
	for _, ix := range instructions {
		out = append(out, ix.program)
		out = append(out, solanaEncodeShortVec(uint64(len(ix.accs)))...)
		out = append(out, ix.accs...)
		out = append(out, solanaEncodeShortVec(uint64(len(ix.data)))...)
		out = append(out, ix.data...)
	}
	return out, nil
}

func solanaEncodeShortVec(v uint64) []byte {
	out := make([]byte, 0, 10)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			out = append(out, b)
			return out
		}
		out = append(out, b|0x80)
	}
}

func solanaSignAndAttachSignatureByAddress(s *signer.Signer, txBytes, messageBytes []byte, signerAddr string) ([]byte, string, error) {
	if s == nil {
		return nil, "", errors.New("missing signer")
	}
	if len(txBytes) == 0 || len(messageBytes) == 0 {
		return nil, "", errors.New("missing solana transaction/message bytes")
	}
	signerAddr = strings.TrimSpace(signerAddr)
	if signerAddr == "" {
		return nil, "", errors.New("missing solana signer address")
	}

	sigCount, n, err := solanaDecodeShortVec(txBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode signature count: %w", err)
	}
	if sigCount == 0 {
		return nil, "", errors.New("solana transaction has zero signatures")
	}
	sigSectionEnd := n + int(sigCount)*64
	if sigSectionEnd > len(txBytes) {
		return nil, "", errors.New("solana transaction truncated at signatures section")
	}
	meta, err := solanaParseMessageMeta(messageBytes)
	if err != nil {
		return nil, "", err
	}
	if int(meta.RequiredSignatures) != int(sigCount) {
		return nil, "", fmt.Errorf("signature count mismatch: tx=%d message=%d", sigCount, meta.RequiredSignatures)
	}
	signerIndex := -1
	for i, addr := range meta.Signers {
		if addr == signerAddr {
			signerIndex = i
			break
		}
	}
	if signerIndex < 0 {
		return nil, "", fmt.Errorf("failed to locate signer %s in solana signer set %v", signerAddr, meta.Signers)
	}
	if signerIndex >= int(sigCount) {
		return nil, "", fmt.Errorf("signer index %d exceeds signature count %d", signerIndex, sigCount)
	}
	slotOffset := n + signerIndex*64
	if slotOffset+64 > sigSectionEnd {
		return nil, "", errors.New("solana signer slot out of bounds")
	}

	signReq := signer.SignRequest{
		Chain:        "solana",
		SignMode:     "transaction",
		TxPayloadHex: "0x" + hex.EncodeToString(messageBytes),
	}
	if err := PopulateSigningShares(&signReq); err != nil {
		return nil, "", err
	}
	signRes, err := s.Sign(&signReq)
	if err != nil {
		return nil, "", err
	}

	sigBytes, err := hex.DecodeString(signRes.SignatureHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid solana signature hex: %w", err)
	}
	if len(sigBytes) != 64 {
		return nil, "", fmt.Errorf("unexpected solana signature length %d", len(sigBytes))
	}

	out := make([]byte, len(txBytes))
	copy(out, txBytes)
	copy(out[slotOffset:slotOffset+64], sigBytes)
	return out, signRes.SignatureHex, nil
}

func extractSolanaSignatureBase58ByAddressFromRawTxBase64(rawTxBase64, signerAddr string) (string, error) {
	signerAddr = strings.TrimSpace(signerAddr)
	if signerAddr == "" {
		return "", errors.New("missing solana signer address")
	}
	txBytes, err := decodeBase64Payload(rawTxBase64)
	if err != nil {
		return "", fmt.Errorf("invalid solana raw transaction base64: %w", err)
	}
	sigCount, n, err := solanaDecodeShortVec(txBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decode solana signature count: %w", err)
	}
	if sigCount == 0 {
		return "", errors.New("solana transaction has zero signatures")
	}
	sigSectionEnd := n + int(sigCount)*64
	if sigSectionEnd > len(txBytes) {
		return "", errors.New("solana transaction truncated at signatures section")
	}
	messageBytes := txBytes[sigSectionEnd:]
	meta, err := solanaParseMessageMeta(messageBytes)
	if err != nil {
		return "", err
	}
	if int(meta.RequiredSignatures) != int(sigCount) {
		return "", fmt.Errorf("signature count mismatch: tx=%d message=%d", sigCount, meta.RequiredSignatures)
	}
	signerIndex := -1
	for i, addr := range meta.Signers {
		if addr == signerAddr {
			signerIndex = i
			break
		}
	}
	if signerIndex < 0 {
		return "", fmt.Errorf("failed to locate signer %s in solana signer set %v", signerAddr, meta.Signers)
	}
	if signerIndex >= int(sigCount) {
		return "", fmt.Errorf("signer index %d exceeds signature count %d", signerIndex, sigCount)
	}
	slotOffset := n + signerIndex*64
	if slotOffset+64 > sigSectionEnd {
		return "", errors.New("solana signer slot out of bounds")
	}
	slot := txBytes[slotOffset : slotOffset+64]
	isZero := true
	for _, b := range slot {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return "", errors.New("solana signer signature is zero")
	}
	return base58.Encode(slot), nil
}

func solanaParseMessageMeta(message []byte) (*solanaMessageMeta, error) {
	if len(message) < 4 {
		return nil, errors.New("solana message too short")
	}
	i := 0
	versioned := false
	version := byte(0)
	if message[0]&0x80 != 0 {
		versioned = true
		version = message[0] & 0x7f
		i++
	}

	if i+3 > len(message) {
		return nil, errors.New("solana message missing header")
	}
	required := message[i]
	i += 3

	keyCountU64, n, err := solanaDecodeShortVec(message[i:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode account keys length: %w", err)
	}
	i += n
	if keyCountU64 == 0 {
		return nil, errors.New("solana message has zero account keys")
	}
	keyCount := int(keyCountU64)
	if i+keyCount*32 > len(message) {
		return nil, errors.New("solana message truncated at account keys")
	}

	keys := make([][]byte, 0, keyCount)
	for k := 0; k < keyCount; k++ {
		key := message[i : i+32]
		i += 32
		cp := make([]byte, 32)
		copy(cp, key)
		keys = append(keys, cp)
	}

	if i+32 > len(message) {
		return nil, errors.New("solana message missing recent blockhash")
	}
	i += 32

	insCountU64, n, err := solanaDecodeShortVec(message[i:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode instruction count: %w", err)
	}
	i += n

	programs := map[string]struct{}{}
	for ix := 0; ix < int(insCountU64); ix++ {
		if i >= len(message) {
			return nil, errors.New("solana message truncated at instruction")
		}
		programIndex := int(message[i])
		i++
		if programIndex < 0 || programIndex >= len(keys) {
			return nil, errors.New("solana message instruction program index out of range")
		}
		programs[base58.Encode(keys[programIndex])] = struct{}{}

		accLenU64, n, err := solanaDecodeShortVec(message[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode instruction accounts length: %w", err)
		}
		i += n
		if i+int(accLenU64) > len(message) {
			return nil, errors.New("solana message truncated at instruction accounts")
		}
		i += int(accLenU64)

		dataLenU64, n, err := solanaDecodeShortVec(message[i:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode instruction data length: %w", err)
		}
		i += n
		if i+int(dataLenU64) > len(message) {
			return nil, errors.New("solana message truncated at instruction data")
		}
		i += int(dataLenU64)
	}

	requiredN := int(required)
	if requiredN <= 0 || requiredN > len(keys) {
		return nil, errors.New("solana message invalid required signatures")
	}

	signers := make([]string, 0, requiredN)
	for s := 0; s < requiredN; s++ {
		signers = append(signers, base58.Encode(keys[s]))
	}

	programIDs := make([]string, 0, len(programs))
	for pid := range programs {
		programIDs = append(programIDs, pid)
	}

	return &solanaMessageMeta{
		Versioned:          versioned,
		Version:            version,
		RequiredSignatures: required,
		Payer:              base58.Encode(keys[0]),
		Signers:            signers,
		ProgramIDs:         programIDs,
	}, nil
}

func solanaDecodeShortVec(data []byte) (uint64, int, error) {
	var out uint64
	var shift uint
	for i := 0; i < len(data); i++ {
		b := data[i]
		out |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return out, i + 1, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, errors.New("shortvec overflow")
		}
	}
	return 0, 0, errors.New("shortvec truncated")
}

func validateJupiterPrograms(programIDs []string) (string, error) {
	if len(programIDs) == 0 {
		return "", errors.New("swap transaction does not reference any program id")
	}

	firstAllowed := ""
	for _, pid := range programIDs {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}
		if _, ok := jupiterProgramAllowlist[pid]; !ok {
			return "", fmt.Errorf("swap transaction references non-allowlisted program id %s", pid)
		}
		if firstAllowed == "" {
			firstAllowed = pid
		}
	}
	if firstAllowed == "" {
		return "", errors.New("swap transaction does not reference an allowed jupiter program id")
	}
	return firstAllowed, nil
}

func fetchCetusSwapTxBytes(swapURL string, body *cetusSwapBuildRequest) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(swapURL), bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", fmt.Errorf("cetus swap_v3 request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("cetus swap_v3 http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return parseCetusSwapPayload(raw)
}

func parseCetusRoutesPayload(raw []byte) (string, string, string, error) {
	data, code, msg, err := cetusDecodeAPIResponse(raw)
	if err != nil {
		return "", "", "", err
	}
	if code != 0 && code != 200 {
		return "", "", "", fmt.Errorf("cetus find_routes code %d: %s", code, msg)
	}
	requestID := cetusFindString(data, "request_id", "requestId")
	amountIn := cetusFindString(data, "amount_in", "amountIn")
	amountOut := cetusFindString(data, "amount_out", "amountOut")
	if requestID == "" {
		return "", "", "", errors.New("cetus find_routes response missing request_id")
	}
	return requestID, amountIn, amountOut, nil
}

func parseCetusSwapPayload(raw []byte) (string, error) {
	data, code, msg, err := cetusDecodeAPIResponse(raw)
	if err != nil {
		return "", err
	}
	if code != 0 && code != 200 {
		return "", fmt.Errorf("cetus swap_v3 code %d: %s", code, msg)
	}
	tx := cetusFindString(data, "data", "txBytes", "tx_bytes", "txbytes", "tx")
	if tx == "" {
		return "", errors.New("cetus swap_v3 response missing tx bytes")
	}
	if _, err := base64.StdEncoding.DecodeString(tx); err != nil {
		return "", fmt.Errorf("invalid cetus tx bytes base64: %w", err)
	}
	return tx, nil
}

func cetusDecodeAPIResponse(raw []byte) (map[string]any, int, string, error) {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, "", fmt.Errorf("failed to decode cetus response: %w", err)
	}
	msg := strings.TrimSpace(cetusFindString(out, "msg", "message", "error"))
	code := 0
	if v, ok := out["code"]; ok {
		switch c := v.(type) {
		case float64:
			code = int(c)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
				code = n
			}
		}
	}
	return out, code, msg, nil
}

func cetusFindString(node any, keys ...string) string {
	set := map[string]struct{}{}
	for _, k := range keys {
		set[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
	}
	var walk func(any) string
	walk = func(cur any) string {
		switch v := cur.(type) {
		case map[string]any:
			for k, val := range v {
				if _, ok := set[strings.ToLower(strings.TrimSpace(k))]; ok {
					if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
						return strings.TrimSpace(s)
					}
				}
			}
			for _, val := range v {
				if s := walk(val); s != "" {
					return s
				}
			}
		case []any:
			for _, val := range v {
				if s := walk(val); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return walk(node)
}

func isEVMUniversalRouter(chain, router string) bool {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if !common.IsHexAddress(router) {
		return false
	}
	want, ok := evmUniversalRouterByChain[chain]
	if !ok || len(want) == 0 {
		return false
	}
	got := common.HexToAddress(router).Hex()
	for _, addr := range want {
		if common.IsHexAddress(addr) && got == common.HexToAddress(addr).Hex() {
			return true
		}
	}
	return false
}

func defaultEVMUniversalRouter(chain string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	list, ok := evmUniversalRouterByChain[chain]
	if !ok || len(list) == 0 {
		return ""
	}
	addr := strings.TrimSpace(list[0])
	if !common.IsHexAddress(addr) {
		return ""
	}
	return common.HexToAddress(addr).Hex()
}

func jupiterAPIKey() string {
	return strings.TrimSpace(env("JUPITER_API_KEY", ""))
}

func uniswapAPIKey() string {
	return strings.TrimSpace(env("UNISWAP_TRADE_API_KEY", ""))
}
