package handlers

import (
	"encoding/json"
	"net/http"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sync"
)

// 提供依赖注入
type RuntimeState struct {
	SandboxServer        *http.Server
	PolicyEngine         *policy.Engine
	Mu                   *sync.RWMutex
	RelayURL             string
	EncShare1            signer.EncryptedShare
	EncShare3            signer.EncryptedShare
	MasterPubKey         string
	Addresses            map[string]string
	BoundUid             string
	SekKey               []byte
	RemoteManaged        bool
	BuildVersion         string
	UpgradeScriptBaseURL string
}

// EVM 调用请求参数
type ManagedEVMInvokeRequest struct {
	UID             string `json:"uid,omitempty"`
	Chain           string `json:"chain,omitempty"`
	SignMode        string `json:"sign_mode,omitempty"`
	To              string `json:"to"`
	Value           string `json:"value,omitempty"`
	Data            string `json:"data,omitempty"`
	ConfirmedByUser bool   `json:"confirmed_by_user,omitempty"`
}

// EVM 调用响应结果
type ManagedEVMTxResponse struct {
	Chain       string `json:"chain"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	SubmittedID string `json:"submitted_id,omitempty"`
	TxHash      string `json:"tx_hash,omitempty"`
	Signature   string `json:"signature,omitempty"`
	TxPayload   string `json:"tx_payload,omitempty"`
	RawTxHex    string `json:"raw_tx_hex,omitempty"`
	Sponsored   bool   `json:"sponsored,omitempty"`
}

// Solana 调用请求参数
type ManagedSolInvokeRequest struct {
	UID              string `json:"uid,omitempty"`
	Chain            string `json:"chain,omitempty"`
	SignMode         string `json:"sign_mode,omitempty"`
	To               string `json:"to,omitempty"`
	Value            string `json:"value,omitempty"`
	Data             string `json:"data,omitempty"`
	UnsignedTxBase64 string `json:"unsigned_tx_base64,omitempty"`
	UnsignedTxHex    string `json:"unsigned_tx_hex,omitempty"`
	TxPayloadBase64  string `json:"tx_payload_base64,omitempty"`
	TxPayloadHex     string `json:"tx_payload_hex,omitempty"`
	ConfirmedByUser  bool   `json:"confirmed_by_user,omitempty"`
}

// Solana 调用响应结果
type ManagedSolTxResponse struct {
	Chain       string `json:"chain"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	SubmittedID string `json:"submitted_id,omitempty"`
	TxHash      string `json:"tx_hash,omitempty"`
	Signature   string `json:"signature,omitempty"`
	TxPayload   string `json:"tx_payload,omitempty"`
	RawTxBase64 string `json:"raw_tx_base64,omitempty"`
	Sponsored   bool   `json:"sponsored"`
}

// 通用转账请求（多链）
type TransferRequest struct {
	Chain          string `json:"chain"`
	UID            string `json:"uid,omitempty"`
	To             string `json:"to"`
	AmountWei      string `json:"amount_wei"`
	TokenContract  string `json:"token_contract,omitempty"`
	SuiGasBudget   string `json:"sui_gas_budget,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
	ExecutionToken string `json:"execution_token,omitempty"`
}

// 通用转账响应（多链）
type TransferResponse struct {
	Chain         string `json:"chain"`
	From          string `json:"from"`
	To            string `json:"to"`
	AmountWei     string `json:"amount_wei"`
	TokenContract string `json:"token_contract,omitempty"`
	SubmittedID   string `json:"submitted_id"`
	TxHash        string `json:"tx_hash,omitempty"`
	Signature     string `json:"signature,omitempty"`
	Digest        string `json:"digest,omitempty"`
	TxPayloadHex  string `json:"tx_payload_hex,omitempty"`
	RawTxHex      string `json:"raw_tx_hex,omitempty"`
	RawTxBase64   string `json:"raw_tx_base64,omitempty"`
	TxBytesBase64 string `json:"tx_bytes_base64,omitempty"`
	Sponsored     bool   `json:"sponsored"`
}

// share2 审计摘要信息
type share2AuditSummary struct {
	IsPlainText    bool     `json:"is_plain_text"`
	MessagePreview string   `json:"message_preview,omitempty"`
	To             string   `json:"to,omitempty"`
	AmountWei      string   `json:"amount_wei,omitempty"`
	AmountUSD      float64  `json:"amount_usd,omitempty"`
	TokenContract  string   `json:"token_contract,omitempty"`
	ContractAddr   string   `json:"contract_address,omitempty"`
	DecodedMethod  string   `json:"decoded_method,omitempty"`
	RiskFlags      []string `json:"risk_flags,omitempty"`
}

// share2 网关请求体
type share2GateRelayRequest struct {
	UID             string             `json:"uid"`
	Chain           string             `json:"chain"`
	SignMode        string             `json:"sign_mode"`
	ConfirmedByUser bool               `json:"confirmed_by_user,omitempty"`
	IsUserApproval  bool               `json:"is_user_approval,omitempty"`
	ApprovalID      string             `json:"approval_id,omitempty"`
	ExecutionToken  string             `json:"execution_token,omitempty"`
	IntentPayload   string             `json:"intent_payload,omitempty"`
	Audit           share2AuditSummary `json:"audit"`
}

// share2 网关响应体
type share2GateRelayResponse struct {
	Status        string `json:"status"`
	ReasonCode    string `json:"reason_code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ApprovalID    string `json:"approval_id,omitempty"`
	Error         string `json:"error,omitempty"`
	WrappedShare2 string `json:"wrapped_share2_hex,omitempty"`
	Nonce         string `json:"nonce_hex,omitempty"`
}

// Haedal txBytes 执行请求
type HaedalTxBytesExecuteRequest struct {
	UID           string `json:"uid,omitempty"`
	TxBytes       string `json:"txBytes,omitempty"`
	TxBytesBase64 string `json:"tx_bytes_base64,omitempty"`
	TxBytesHex    string `json:"tx_bytes_hex,omitempty"`
}

// Haedal Sui 执行响应
type HaedalSuiTxResponse struct {
	Chain     string `json:"chain"`
	From      string `json:"from"`
	Action    string `json:"action"`
	Amount    string `json:"amount,omitempty"`
	NFTObj    string `json:"nft_obj,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Sponsored bool   `json:"sponsored"`
}

// Haedal 选项化请求
type HaedalOptionedRequest struct {
	UID    string         `json:"uid,omitempty"`
	Option string         `json:"option"`
	Defi   string         `json:"defi"`
	Body   map[string]any `json:"body"`
}

// Haedal txBytes 接口响应
type haedalTxBytesResponse struct {
	TxBytes string `json:"txBytes"`
}

// Haedal API 错误响应
type haedalAPIError struct {
	Msg string `json:"msg"`
}

// Haedal 赎回票据列表响应
type haedalUnstakeTicketsListResponse struct {
	List []struct {
		ObjectId string `json:"objectId"`
	} `json:"list"`
}

// Haedal ve 资产列表响应
type haedalVehaedalListResponse struct {
	List []struct {
		ObjectId string `json:"objectId"`
	} `json:"list"`
}

// Haedal 质押请求
type HaedalStakeRequest struct {
	UID       string `json:"uid,omitempty"`
	Amount    string `json:"amount"`
	Validator string `json:"validator,omitempty"`
}

// Haedal 提现请求
type HaedalWithdrawRequest struct {
	UID    string `json:"uid,omitempty"`
	Amount string `json:"amount"`
}

// Haedal 领奖请求
type HaedalClaimRequest struct {
	UID    string `json:"uid,omitempty"`
	NFTObj string `json:"nft_obj,omitempty"`
}

// Haedal ve 新增质押请求
type HaedalVeHaedalAddStakeRequest struct {
	UID        string `json:"uid,omitempty"`
	Amount     string `json:"amount"`
	LockWeeks  int    `json:"lock_weeks"`
	IsDecaying bool   `json:"is_decaying"`
}

// Haedal ve 追加金额请求
type HaedalVeHaedalObjAmountRequest struct {
	UID         string `json:"uid,omitempty"`
	VehaedalObj string `json:"vehaedal_obj,omitempty"`
	Amount      string `json:"amount"`
}

// Haedal ve 延长锁仓请求
type HaedalVeHaedalExtendLockRequest struct {
	UID             string `json:"uid,omitempty"`
	VehaedalObj     string `json:"vehaedal_obj,omitempty"`
	AdditionalWeeks int    `json:"additional_weeks"`
}

// Haedal ve 对象请求
type HaedalVeHaedalObjRequest struct {
	UID         string `json:"uid,omitempty"`
	VehaedalObj string `json:"vehaedal_obj,omitempty"`
}

// Haedal ve v2 奖励领取请求
type HaedalVeHaedalClaimRewardsV2Request struct {
	UID     string   `json:"uid,omitempty"`
	Periods []string `json:"periods"`
}

// share2 网关业务错误
type Share2GateError struct {
	status int
	reason string
}

type UniswapSwapTradeAPIRequest struct {
	Chain             string   `json:"chain"`
	UID               string   `json:"uid,omitempty"`
	TokenIn           string   `json:"token_in"`
	TokenOut          string   `json:"token_out"`
	AmountInWei       string   `json:"amount_in_wei"`
	RoutingPreference string   `json:"routing_preference,omitempty"`
	Protocols         []string `json:"protocols,omitempty"`
	Urgency           string   `json:"urgency,omitempty"`
	AutoSlippage      string   `json:"auto_slippage,omitempty"`
	SlippageTolerance uint16   `json:"slippage_tolerance,omitempty"`
	PermitAmount      string   `json:"permit_amount,omitempty"`
}

type UniswapTradeTx struct {
	To      string `json:"to"`
	From    string `json:"from,omitempty"`
	Data    string `json:"data"`
	Value   string `json:"value,omitempty"`
	ChainID int    `json:"chainId,omitempty"`
}

type UniswapTradeExecutionResult struct {
	Tx          *UniswapTradeTx `json:"tx,omitempty"`
	SubmittedID string          `json:"submitted_id,omitempty"`
	TxHash      string          `json:"tx_hash,omitempty"`
}

type UniswapTradeApprovalRequest struct {
	WalletAddress   string `json:"walletAddress"`
	Token           string `json:"token"`
	Amount          string `json:"amount"`
	ChainID         int    `json:"chainId"`
	TokenOut        string `json:"tokenOut,omitempty"`
	TokenOutChainID int    `json:"tokenOutChainId,omitempty"`
}

type UniswapTradeApprovalResponse struct {
	RequestID string          `json:"requestId,omitempty"`
	Cancel    *UniswapTradeTx `json:"cancel,omitempty"`
	Approval  *UniswapTradeTx `json:"approval,omitempty"`
}

type UniswapTradeQuoteRequest struct {
	Swapper                     string   `json:"swapper"`
	TokenInChainID              int      `json:"tokenInChainId"`
	TokenOutChainID             int      `json:"tokenOutChainId"`
	TokenIn                     string   `json:"tokenIn"`
	TokenOut                    string   `json:"tokenOut"`
	Amount                      string   `json:"amount"`
	Type                        string   `json:"type"`
	RoutingPreference           string   `json:"routingPreference,omitempty"`
	Protocols                   []string `json:"protocols,omitempty"`
	Urgency                     string   `json:"urgency,omitempty"`
	PermitAmount                string   `json:"permitAmount,omitempty"`
	AutoSlippage                string   `json:"autoSlippage,omitempty"`
	SlippageTolerance           *int     `json:"slippageTolerance,omitempty"`
	GeneratePermitAsTransaction *bool    `json:"generatePermitAsTransaction,omitempty"`
}

type UniswapTradeQuoteResponse struct {
	RequestID         string          `json:"requestId,omitempty"`
	QuoteID           string          `json:"quoteId,omitempty"`
	Routing           string          `json:"routing,omitempty"`
	Quote             json.RawMessage `json:"quote"`
	PermitData        json.RawMessage `json:"permitData,omitempty"`
	PermitTransaction *UniswapTradeTx `json:"permitTransaction,omitempty"`
}

type UniswapTradeSwapRequest struct {
	Signature           string          `json:"signature,omitempty"`
	Quote               json.RawMessage `json:"quote"`
	PermitData          json.RawMessage `json:"permitData,omitempty"`
	SimulateTransaction *bool           `json:"simulateTransaction,omitempty"`
}

type UniswapTradeSwapResponse struct {
	RequestID string          `json:"requestId,omitempty"`
	Swap      *UniswapTradeTx `json:"swap,omitempty"`
}

type UniswapTradeOrderRequest struct {
	Signature string          `json:"signature,omitempty"`
	Quote     json.RawMessage `json:"quote"`
}

type UniswapTradeOrderResponse struct {
	RequestID   string `json:"requestId,omitempty"`
	OrderID     string `json:"orderId,omitempty"`
	OrderStatus string `json:"orderStatus,omitempty"`
}

type UniswapSwapTradeAPIResponse struct {
	Chain            string                       `json:"chain"`
	From             string                       `json:"from"`
	RequestID        string                       `json:"request_id,omitempty"`
	Routing          string                       `json:"routing,omitempty"`
	TokenIn          string                       `json:"token_in"`
	TokenOut         string                       `json:"token_out"`
	AmountInWei      string                       `json:"amount_in_wei"`
	ApprovalRequired bool                         `json:"approval_required"`
	ApprovalReset    *UniswapTradeExecutionResult `json:"approval_reset,omitempty"`
	Approval         *UniswapTradeExecutionResult `json:"approval,omitempty"`
	Permit           *UniswapTradeExecutionResult `json:"permit,omitempty"`
	Order            *UniswapTradeOrderResponse   `json:"order,omitempty"`
	Swap             *UniswapTradeExecutionResult `json:"swap,omitempty"`
}

// 策略更新提交包
type PolicyUpdatePackage struct {
	NewPolicy json.RawMessage       `json:"new_policy"`
	AuthPIN   string                `json:"auth_pin"`
	EncShare1 signer.EncryptedShare `json:"enc_share1"`
}

// Jupiter 交换请求
type JupiterSwapRequest struct {
	Chain                   string `json:"chain"`
	UID                     string `json:"uid,omitempty"`
	TokenIn                 string `json:"token_in"`
	TokenOut                string `json:"token_out"`
	AmountInWei             string `json:"amount_in_wei"`
	SlippageBps             uint16 `json:"slippage_bps,omitempty"`
	AsLegacyTransaction     bool   `json:"as_legacy_transaction,omitempty"`
	WrapAndUnwrapSol        *bool  `json:"wrap_and_unwrap_sol,omitempty"`
	UseSharedAccounts       *bool  `json:"use_shared_accounts,omitempty"`
	DynamicComputeUnitLimit *bool  `json:"dynamic_compute_unit_limit,omitempty"`
}

// Jupiter 交换响应
type JupiterSwapResponse struct {
	Chain                string `json:"chain"`
	From                 string `json:"from"`
	TokenIn              string `json:"token_in"`
	TokenOut             string `json:"token_out"`
	AmountInWei          string `json:"amount_in_wei"`
	SlippageBps          uint16 `json:"slippage_bps"`
	InAmount             string `json:"in_amount,omitempty"`
	OutAmount            string `json:"out_amount,omitempty"`
	OtherAmountThreshold string `json:"other_amount_threshold,omitempty"`
	SwapMode             string `json:"swap_mode,omitempty"`
	AsLegacyTransaction  bool   `json:"as_legacy_transaction"`
	UsedVersionedTx      bool   `json:"used_versioned_tx"`
	JupiterProgram       string `json:"jupiter_program"`
	SwapTxBase64         string `json:"swap_tx_base64,omitempty"`
	MessageHex           string `json:"message_hex,omitempty"`
	SubmittedID          string `json:"submitted_id,omitempty"`
	Signature            string `json:"signature,omitempty"`
	LastValidBlockHeight uint64 `json:"last_valid_block_height,omitempty"`
	Sponsored            bool   `json:"sponsored"`
}

// Jupiter 报价响应
type jupiterQuoteResponse struct {
	InputMint            string          `json:"inputMint"`
	OutputMint           string          `json:"outputMint"`
	InAmount             string          `json:"inAmount"`
	OutAmount            string          `json:"outAmount"`
	OtherAmountThreshold string          `json:"otherAmountThreshold"`
	SwapMode             string          `json:"swapMode"`
	SlippageBps          int             `json:"slippageBps"`
	RoutePlan            json.RawMessage `json:"routePlan"`
}

// Jupiter 交换构建请求体
type jupiterSwapBody struct {
	UserPublicKey           string          `json:"userPublicKey"`
	QuoteResponse           json.RawMessage `json:"quoteResponse"`
	WrapAndUnwrapSol        bool            `json:"wrapAndUnwrapSol"`
	UseSharedAccounts       bool            `json:"useSharedAccounts"`
	DynamicComputeUnitLimit bool            `json:"dynamicComputeUnitLimit"`
	AsLegacyTransaction     bool            `json:"asLegacyTransaction"`
}

// Jupiter 交换构建响应体
type jupiterSwapResponse struct {
	SwapTransaction      string `json:"swapTransaction"`
	LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
}

// Cetus 交换请求
type CetusSwapRequest struct {
	Chain     string  `json:"chain"`
	UID       string  `json:"uid,omitempty"`
	TokenIn   string  `json:"token_in"`
	TokenOut  string  `json:"token_out"`
	AmountWei string  `json:"amount_wei"`
	Slippage  float64 `json:"slippage,omitempty"`
}

// Cetus 交换响应
type CetusSwapResponse struct {
	Chain          string  `json:"chain"`
	From           string  `json:"from"`
	Wallet         string  `json:"wallet"`
	TokenIn        string  `json:"token_in"`
	TokenOut       string  `json:"token_out"`
	AmountWei      string  `json:"amount_wei"`
	ByAmountIn     bool    `json:"by_amount_in"`
	Slippage       float64 `json:"slippage"`
	RequestID      string  `json:"request_id"`
	QuoteAmountIn  string  `json:"quote_amount_in,omitempty"`
	QuoteAmountOut string  `json:"quote_amount_out,omitempty"`
	TxBytesBase64  string  `json:"tx_bytes_base64,omitempty"`
	Digest         string  `json:"digest,omitempty"`
	Sponsored      bool    `json:"sponsored"`
}

// Cetus 路由查询内部请求
type cetusFindRoutesRequest struct {
	From   string
	Target string
	Amount string
}

// Cetus 交易构建内部请求
type cetusSwapBuildRequest struct {
	RequestID string  `json:"request_id"`
	Wallet    string  `json:"wallet"`
	Slippage  float64 `json:"slippage"`
}

// Solana 消息元信息
type solanaMessageMeta struct {
	Versioned          bool
	Version            byte
	RequiredSignatures uint8
	Payer              string
	Signers            []string
	ProgramIDs         []string
}

// LI.FI 跨链通用请求 (预估和执行接口共用)
type LifiBridgeRequest struct {
	// 起始链 ID (LI.FI 标准 ID)。
	// 常用链 ID 说明:
	// ETH: "1", BSC: "56", Base: "8453", Arbitrum: "42161", Optimism: "10", Polygon: "137"
	// Solana: "1151111081099710"
	// Sui: "9270000000000000"
	// Bitcoin: "20000000000001"
	FromChainID string `json:"from_chain_id"`
	FromAddress string `json:"from_address"` // 起始钱包地址
	FromToken   string `json:"from_token"`   // 起始 Token 地址或名字
	Amount      string `json:"amount"`       // 交易金额 (最小精度)
	// 目标链 ID (LI.FI 标准 ID)。常用链 ID 说明同上。
	ToChainID string  `json:"to_chain_id"`
	ToAddress string  `json:"to_address"`           // 目标钱包地址
	ToToken   string  `json:"to_token"`             // 目标 Token 地址或名字
	Slippage  float64 `json:"slippage,omitempty"`   // 滑点 (可选，默认 0.005)
	ViaSolana bool    `json:"via_solana,omitempty"` // 是否使用 Solana 中转 (用于 EVM -> Sui)
}

// 跨链路由步骤明细
type LifiRouteStep struct {
	Tool          string  `json:"tool"`           // 使用的跨链桥或 DEX
	FromToken     string  `json:"from_token"`     // 步骤源代币
	ToToken       string  `json:"to_token"`       // 步骤目标代币
	EstimatedTime float64 `json:"estimated_time"` // 该步骤预计耗时(秒)
}

// LI.FI 预估/报价响应
type LifiQuoteResponse struct {
	IsSuccess         bool            `json:"is_success"`         // 跨链是否能够成功
	Reason            string          `json:"reason,omitempty"`   // 如果不能成功，返回失败原因
	Tool              string          `json:"tool,omitempty"`     // 主跨链桥名称
	Steps             []LifiRouteStep `json:"steps,omitempty"`    // 路由步骤明细
	EstimatedDuration float64         `json:"estimated_duration"` // 预计总耗时(秒)
	AmountIn          string          `json:"amount_in"`          // 预计消耗的源代币（展示值，已按 decimals 格式化）
	AmountOut         string          `json:"amount_out"`         // 预计获取的目标代币（展示值，已按 decimals 格式化）
	AmountInRaw       string          `json:"amount_in_raw,omitempty"`
	AmountOutRaw      string          `json:"amount_out_raw,omitempty"`
	AmountInSymbol    string          `json:"amount_in_symbol,omitempty"`
	AmountOutSymbol   string          `json:"amount_out_symbol,omitempty"`
	AmountInDecimals  int             `json:"amount_in_decimals,omitempty"`
	AmountOutDecimals int             `json:"amount_out_decimals,omitempty"`
}

// 跨链执行步骤明细
type LifiExecuteStep struct {
	FromChainID string `json:"from_chain_id"`
	ToChainID   string `json:"to_chain_id"`
	TxHash      string `json:"tx_hash"`
	Status      string `json:"status"`
	StatusURL   string `json:"status_url,omitempty"`
}

// LI.FI 实际执行响应
type LifiBridgeResponse struct {
	UID            string            `json:"uid"`
	Success        bool              `json:"success"`
	Status         string            `json:"status,omitempty"`
	Message        string            `json:"message,omitempty"`
	Steps          []LifiExecuteStep `json:"steps,omitempty"`
	FinalTxHash    string            `json:"final_tx_hash,omitempty"`
	FinalStatusURL string            `json:"final_status_url,omitempty"`
}

// LI.FI 状态查询请求
type LifiStatusRequest struct {
	UID string `json:"uid"`
}

// LI.FI 状态查询响应
type LifiStatusResponse struct {
	Status         string            `json:"status"` // PENDING, DONE, FAILED, NOT_FOUND
	Message        string            `json:"message,omitempty"`
	Steps          []LifiExecuteStep `json:"steps,omitempty"`
	FinalTxHash    string            `json:"final_tx_hash,omitempty"`
	FinalStatusURL string            `json:"final_status_url,omitempty"`
}

type localPolicyUpdateRequest struct {
	MaxAmountPerTxUSD   *float64              `json:"max_amount_per_tx_usd"`
	DailyLimitUSD       *float64              `json:"daily_limit_usd"`
	DailyMaxTxCount     *int                  `json:"daily_max_tx_count"`
	WhitelistTo         *[]policy.AddressNote `json:"whitelist_to"`
	BlacklistTo         *[]policy.AddressNote `json:"blacklist_to"`
	UnpricedAssetPolicy *string               `json:"unpriced_asset_policy"`
	AllowBlindSign      *bool                 `json:"allow_blind_sign"`
	StrictPlainText     *bool                 `json:"strict_plain_text"`
}
