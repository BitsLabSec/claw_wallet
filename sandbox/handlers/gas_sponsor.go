package handlers

import (
	"context"
	"fmt"
	"os"
	"sandbox/internals/signer"
	"sandbox/internals/sponsor"
	"strconv"
	"strings"
	"time"
)

// BuildResult 表示一次构建与签名的结果
type BuildResult struct {
	TxBase64  string
	Signature string
}

// SponsorSubmitRequest 代付系统统一的上链请求参数
type SponsorSubmitRequest struct {
	Chain       string
	FromAddress string
	UID         string
	Options     []byte // 透传给普通广播的 Options，例如 Sui 的 showEffects
}

// SubmitAndBroadcastResponse 统一的上链返回结果
type SubmitAndBroadcastResponse struct {
	TxHash      string
	SubmittedID string
	Sponsored   bool // 标记该交易是否触发了代付
}

// TxBuilder 业务层提供的闭包：构建并真实签名原交易
// sponsorAddr: 当非空时，表示需要将该地址设为交易的 Gas Payer / Owner
type TxBuilder func(sponsorAddr string) (*BuildResult, error)

// ChainSponsorAdapter 链适配器接口，屏蔽不同链在余额检查与 USDC 支付构建上的差异
type ChainSponsorAdapter interface {
	// 获取原币和 USDC 的余额 (返回格式统一为 uint64, 即最小单位: lamports, MIST, 以及微USDC)
	GetBalances(ctx context.Context, network, address string) (native uint64, usdc uint64, err error)
	// 构建并签名 USDC 支付交易
	BuildAndSignUSDC(ctx context.Context, network, from, to string, amount uint64, uid string) (*BuildResult, error)
}

// 获取各链的适配器
func getChainAdapter(chain string) (ChainSponsorAdapter, error) {
	chain = strings.ToLower(chain)
	switch chain {
	case "solana":
		return &SolanaSponsorAdapter{}, nil
	case "sui":
		return &SuiSponsorAdapter{}, nil
	case "ethereum", "sepolia", "base", "arbitrum", "optimism", "polygon", "bsc", "avalanche", "linea", "zksync", "monad":
		return &EVMSponsorAdapter{}, nil
	default:
		return nil, fmt.Errorf("gas sponsor not supported for chain: %s", chain)
	}
}

// 获取 Sponsor 服务的 BaseURL，优先使用 GAS_SPONSOR_BASE_URL
func getSponsorBaseURL() string {
	url := os.Getenv("GAS_SPONSOR_BASE_URL")
	// url 必须是 127.0.0.1 或者 localhost 开头
	if url == "" || !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.HasPrefix(url, "http://localhost:") {
		url = "http://127.0.0.1:9351"
	}
	return url
}

func gasSponsorForceEnabled() bool {
	v := strings.TrimSpace(os.Getenv("GAS_SPONSOR_FORCE_ENABLED"))
	if v == "" {
		return false
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return enabled
}

func gasSponsorSettleDelay(chain string) time.Duration {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if msStr := strings.TrimSpace(os.Getenv("GAS_SPONSOR_SETTLE_DELAY_MS")); msStr != "" {
		if ms, err := strconv.Atoi(msStr); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	switch chain {
	case "solana":
		return 2500 * time.Millisecond
	default:
		return 0
	}
}

func resolveGasSponsorNetwork(chain string) string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("GAS_SPONSOR_MODE")))
	if mode == "mainnet" {
		return "mainnet"
	}

	chain = strings.ToLower(strings.TrimSpace(chain))
	switch chain {
	case "solana":
		return "devnet"
	case "sui":
		return "testnet"
	case "base", "arbitrum", "optimism", "polygon", "bsc", "avalanche", "linea", "zksync", "monad":
		return "testnet"
	default:
		return chain
	}
}

// SubmitAndBroadcast 统一调度上链逻辑：静默代付 或 普通广播
func SubmitAndBroadcast(ctx context.Context, req SponsorSubmitRequest, builder TxBuilder) (*SubmitAndBroadcastResponse, error) {
	forceSponsor := gasSponsorForceEnabled()
	adapter, err := getChainAdapter(req.Chain)
	if err != nil {
		// 如果不支持代付，则降级为正常流程
		return broadcastNormally(req, builder)
	}

	network := resolveGasSponsorNetwork(req.Chain)

	// 1. 检查余额
	nativeBal, usdcBal, err := adapter.GetBalances(ctx, network, req.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get balances for gas sponsor: %w", err)
	}

	// 打印查询结果
	fmt.Printf("[GetBalances] address=%s network=%s nativeBalance(wei)=%d usdcBalance(microUSDC)=%d\n",
		req.FromAddress, network, nativeBal, usdcBal)

	// 2. 触发条件：原生代币为 0 且 USDC 余额大于 0 (实际扣除需要估算后判断，此处粗筛)
	if !forceSponsor && (nativeBal > 0 || usdcBal <= 0) {
		// --- 走正常上链流程 ---
		return broadcastNormally(req, builder)
	}

	// --- 走静默代付流程 ---
	isEVMChain := signer.IsEVMChain(req.Chain)
	sponsorChain := req.Chain
	if isEVMChain {
		sponsorChain = "evm" // 统一 EVM 相关链的 sponsor 服务调用参数
	}
	client := sponsor.NewClient(getSponsorBaseURL())
	sponsorAddrs, err := client.GetSponsorInfo()
	fmt.Println("sponsorAddrs:", sponsorAddrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get sponsor info: %w", err)
	}
	sponsorAddr, ok := sponsorAddrs[sponsorChain]
	if !ok || sponsorAddr == "" {
		return nil, fmt.Errorf("sponsor address not configured for chain: %s", sponsorChain)
	}

	// 3. 构造用于估算的原交易 (注入 Sponsor，并进行真实签名)
	estimateRes, err := builder(sponsorAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to build tx for gas estimation: %w", err)
	}

	// 4. 触发 402 估算，获取所需 USDC 手续费
	priceUSD, err := client.EstimateGas(sponsorChain, estimateRes.TxBase64, req.FromAddress, sponsorAddr)
	if err != nil {
		return nil, fmt.Errorf("gas estimation failed: %w", err)
	}

	// Sui 等链的兜底最小代付金额，防止代付金额太小（如 < 0.01 USDC = 10,000）导致问题
	if priceUSD < 10_000 {
		priceUSD = 10_000
	}

	if usdcBal < priceUSD {
		return nil, fmt.Errorf(
			"insufficient USDC balance for gas sponsorship, want=%d, have=%d",
			priceUSD,
			usdcBal,
		)
	}

	// 5. 构造并签名 USDC 支付交易
	paymentRes, err := adapter.BuildAndSignUSDC(ctx, network, req.FromAddress, sponsorAddr, priceUSD, req.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to build bootstrap payment tx: %w", err)
	}

	// 对于 EVM 链且使用 EIP-2612 permit 方式，用户已拥有 ETH 支付 gas 费，无需走 x402 代付服务
	// 直接使用原交易进行普通广播
	if isEVMChain {
		// EVM 使用 permit，已完成链下签名，用户有 gas，直接返回原交易
		return broadcastNormally(req, builder)
	}

	// 6. 提交 Bootstrap 支付交易
	paymentUserSignature := paymentRes.Signature
	if paymentUserSignature == "" {
		return nil, fmt.Errorf("paymentUserSignature is None")
	}

	paymentTxHash, err := client.SubmitBootstrapTx(sponsorChain, paymentRes.TxBase64, req.FromAddress, sponsorAddr, paymentUserSignature, estimateRes.TxBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to submit bootstrap payment tx: %w", err)
	}
	if delay := gasSponsorSettleDelay(req.Chain); delay > 0 {
		time.Sleep(delay)
	}

	// 7. 重新构造原交易并进行真实签名
	// 对于 Sui 来说，这一步非常关键，因为前面的 USDC 转账改变了 Coin Object 的状态
	var finalRes *BuildResult
	if req.Chain == "sui" {
		time.Sleep(3 * time.Second)
		finalRes, err = builder(sponsorAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to build final original tx: %w", err)
		}
		// 同步哈希
		_, err = client.EstimateGas(sponsorChain, finalRes.TxBase64, req.FromAddress, sponsorAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to sync hash via gas estimation: %w", err)
		}
	} else {
		finalRes = estimateRes
	}

	// 8. 携带支付凭证执行最终原交易
	finalUserSignature := finalRes.Signature
	if finalUserSignature == "" {
		return nil, fmt.Errorf("finalUserSignature is None")
	}
	finalTxHash, err := client.ExecuteOriginalTx(sponsorChain, finalRes.TxBase64, req.FromAddress, sponsorAddr, finalUserSignature, paymentTxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to execute original sponsored tx: %w", err)
	}

	return &SubmitAndBroadcastResponse{
		TxHash:      finalTxHash,
		SubmittedID: finalTxHash,
		Sponsored:   true,
	}, nil
}

// 降级为普通广播流程
func broadcastNormally(req SponsorSubmitRequest, builder TxBuilder) (*SubmitAndBroadcastResponse, error) {
	res, err := builder("") // 不注入 sponsorAddr，进行真实签名
	if err != nil {
		return nil, err
	}

	broadcastReq := &BroadcastRequest{
		Chain: req.Chain,
		UID:   req.UID,
	}

	// 根据不同链传递 payload
	if req.Chain == "sui" {
		broadcastReq.TxBytesBase64 = res.TxBase64
		broadcastReq.Signature = res.Signature
		if req.Options != nil {
			broadcastReq.Options = req.Options
		} else {
			broadcastReq.Options = []byte(`{"showEffects":true}`)
		}
	} else if signer.IsEVMChain(req.Chain) {
		broadcastReq.RawTxHex = res.TxBase64 // EVM builder 把 rawTxHex 放在 TxBase64 字段
	} else {
		broadcastReq.RawTxBase64 = res.TxBase64
	}

	broadcastRes, err := BroadcastSignedTransaction(broadcastReq)
	if err != nil {
		return nil, err
	}

	return &SubmitAndBroadcastResponse{
		TxHash:      broadcastRes.TxHash,
		SubmittedID: broadcastRes.SubmittedID,
		Sponsored:   false,
	}, nil
}
