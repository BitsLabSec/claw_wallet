package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sandbox/internals/signer"
	"sandbox/internals/sponsor"
	"strconv"
	"strings"
	"time"

	suimodels "github.com/block-vision/sui-go-sdk/models"
	suiclient "github.com/block-vision/sui-go-sdk/sui"
	"github.com/coming-chat/go-sui/v2/lib"
	suitypes "github.com/coming-chat/go-sui/v2/sui_types"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fardream/go-bcs/bcs"
	solanago "github.com/gagliardetto/solana-go"
	solanatoken "github.com/gagliardetto/solana-go/programs/token"
	solanarpc "github.com/gagliardetto/solana-go/rpc"
)

var USDCContracts = map[string]map[string]string{
	"solana": {
		"devnet":  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		"mainnet": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
	},
	"sui": {
		"devnet":  "0xa198f3be41cda8c07b3bf3fee02263526e535d682499806979a111e88a5a8d0f::coin::COIN", // 待替换为准确的 Sui Devnet USDC
		"mainnet": "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC",
		"testnet": "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC",
	},
}

func getUSDCContract(chain, network string) string {
	contracts, ok := USDCContracts[strings.ToLower(chain)]
	if !ok {
		return ""
	}
	addr, ok := contracts[strings.ToLower(network)]
	if !ok {
		addr = contracts["mainnet"] // fallback
	}
	return addr
}

// ----------------------------------------------------------------------------
// Solana Adapter
// ----------------------------------------------------------------------------

type SolanaSponsorAdapter struct{}

func (a *SolanaSponsorAdapter) GetBalances(ctx context.Context, network, address string) (uint64, uint64, error) {
	rpcURL, err := chainRPCURL("solana")
	if err != nil {
		fmt.Println("[GetBalances] chainRPCURL error: network=%s err=%v", network, err)
		return 0, 0, err
	}

	rpcClient := solanarpc.New(rpcURL)

	pubKey, err := solanago.PublicKeyFromBase58(address)
	if err != nil {
		fmt.Println("[GetBalances] invalid address: address=%s err=%v", address, err)
		return 0, 0, err
	}

	// 1. SOL balance
	balanceResp, err := rpcClient.GetBalance(ctx, pubKey, solanarpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("[GetBalances] GetBalance failed: address=%s err=%v", address, err)
		return 0, 0, err
	}

	native := balanceResp.Value

	// 2. USDC mint
	usdcMintStr := getUSDCContract("solana", network)
	fmt.Println("usdcMintStr = %s", usdcMintStr)
	usdcMint, err := solanago.PublicKeyFromBase58(usdcMintStr)
	if err != nil {
		fmt.Println("[GetBalances] invalid USDC mint: mint=%s network=%s err=%v", usdcMintStr, network, err)
		return native, 0, err
	}

	ata, _, err := solanago.FindAssociatedTokenAddress(pubKey, usdcMint)
	if err != nil {
		fmt.Println("[GetBalances] FindAssociatedTokenAddress failed: owner=%s mint=%s err=%v",
			address, usdcMintStr, err)
		return native, 0, err
	}

	// 3. USDC token balance
	tokenAcc, err := rpcClient.GetTokenAccountBalance(ctx, ata, solanarpc.CommitmentFinalized)
	if err != nil || tokenAcc == nil || tokenAcc.Value == nil {
		fmt.Println("[GetBalances] GetTokenAccountBalance failed or empty: ata=%s err=%v",
			ata.String(), err)

		// 注意：这里是“正常兜底”，不算 fatal error
		return native, 0, nil
	}

	usdcAmtStr := tokenAcc.Value.Amount
	if usdcAmtStr == "" {
		fmt.Println("[GetBalances] empty USDC amount: ata=%s", ata.String())
		return native, 0, nil
	}

	var usdcAmt uint64
	if _, err := fmt.Sscanf(usdcAmtStr, "%d", &usdcAmt); err != nil {
		fmt.Println("[GetBalances] parse USDC amount failed: amount=%s err=%v",
			usdcAmtStr, err)
		return native, 0, nil
	}

	return native, usdcAmt, nil
}
func (a *SolanaSponsorAdapter) BuildAndSignUSDC(ctx context.Context, network, from, to string, amountUSD uint64, uid string) (*BuildResult, error) {
	s, _, _, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	rpcURL, err := chainRPCURL("solana")
	if err != nil {
		return nil, err
	}
	rpcClient := solanarpc.New(rpcURL)

	fromKey, err := solanago.PublicKeyFromBase58(from)
	if err != nil {
		return nil, err
	}
	toKey, err := solanago.PublicKeyFromBase58(to)
	if err != nil {
		return nil, err
	}
	usdcMintStr := getUSDCContract("solana", network)
	mintKey, err := solanago.PublicKeyFromBase58(usdcMintStr)
	if err != nil {
		return nil, err
	}

	// amountUSD 直接是后端的 USDC 的实际金额数值 (1 U = 1,000,000)
	amountInt64 := int64(amountUSD)
	if amountInt64 <= 0 {
		return nil, errors.New("USDC payment amount must be greater than 0")
	}

	recent, err := rpcClient.GetLatestBlockhash(ctx, solanarpc.CommitmentFinalized)
	if err != nil {
		return nil, err
	}

	sourceATA, _, err := solanago.FindAssociatedTokenAddress(fromKey, mintKey)
	if err != nil {
		return nil, err
	}
	destATA, _, err := solanago.FindAssociatedTokenAddress(toKey, mintKey)
	if err != nil {
		return nil, err
	}

	var instructions []solanago.Instruction
	// 检查目标账户(Sponsor)是否存在，不存在则无法进行代付
	destInfo, err := rpcClient.GetAccountInfo(ctx, destATA)
	if err != nil || destInfo == nil || destInfo.Value == nil {
		return nil, fmt.Errorf("sponsor USDC ATA does not exist, cannot proceed with gas sponsorship")
	}

	instructions = append(instructions, solanatoken.NewTransferCheckedInstruction(
		uint64(amountInt64),
		6,
		sourceATA,
		mintKey,
		destATA,
		fromKey,
		nil,
	).Build())

	tx, err := solanago.NewTransaction(
		instructions,
		recent.Value.Blockhash,
		solanago.TransactionPayer(toKey),
	)
	if err != nil {
		return nil, err
	}

	rawTxBase64, err := signManagedSolanaTransaction(s, tx, &signer.SignRequest{
		UID:            uid,
		Chain:          "solana",
		SignMode:       "transaction",
		To:             to,
		TokenContract:  usdcMintStr,
		AmountWei:      strconv.FormatUint(amountUSD, 10),
		IsUserApproval: true,
		ApprovalID:     "",
		ExecutionToken: "",
	})
	if err != nil {
		return nil, err
	}

	fmt.Println("[SolanaSponsor] tx.Message.AccountKeys = %d", len(tx.Message.AccountKeys))
	sigBase58 := ""
	for i, account := range tx.Message.AccountKeys {
		if account.Equals(fromKey) && len(tx.Signatures) > i {
			if tx.Signatures[i].IsZero() {
				return nil, errors.New("extracted signature is zero, signing process may have failed")
			}
			sigBase58 = tx.Signatures[i].String()
			break
		}
	}
	if sigBase58 == "" {
		return nil, errors.New("failed to locate solana user signature by from address")
	}

	return &BuildResult{
		TxBase64:  rawTxBase64,
		Signature: sigBase58,
	}, nil
}

// ----------------------------------------------------------------------------
// Sui Adapter
// ----------------------------------------------------------------------------

type SuiSponsorAdapter struct{}

func (a *SuiSponsorAdapter) GetBalances(ctx context.Context, network, address string) (uint64, uint64, error) {
	rpcURL, err := chainRPCURL("sui")
	if err != nil {
		return 0, 0, err
	}
	client := suiclient.NewSuiClient(rpcURL)

	// 1. 原生 SUI 余额 (MIST)
	totalSUI, err := getSuiTotalBalance(ctx, client, address)
	if err != nil {
		return 0, 0, err
	}
	native := totalSUI.Uint64()

	// 2. USDC 余额
	usdcCoinType := getUSDCContract("sui", network)
	usdcCoins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    address,
		CoinType: usdcCoinType,
		Limit:    50,
	})
	if err != nil {
		return native, 0, err
	}

	usdcTotal := big.NewInt(0)
	for _, coin := range usdcCoins.Data {
		coinAmt, ok := new(big.Int).SetString(strings.TrimSpace(coin.Balance), 10)
		if ok && coinAmt.Sign() > 0 {
			usdcTotal.Add(usdcTotal, coinAmt)
		}
	}
	usdc := usdcTotal.Uint64() // 返回真实最小单位微 USDC

	return native, usdc, nil
}

func (a *SuiSponsorAdapter) BuildAndSignUSDC(ctx context.Context, network, from, to string, amountUSD uint64, uid string) (*BuildResult, error) {
	s, _, _, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}

	rpcURL, err := chainRPCURL("sui")
	if err != nil {
		return nil, err
	}
	client := suiclient.NewSuiClient(rpcURL)

	usdcCoinType := getUSDCContract("sui", network)
	amountInt64 := int64(amountUSD)
	if amountInt64 <= 0 {
		return nil, errors.New("USDC payment amount must be greater than 0")
	}

	gasBudgetStr := defaultSuiGasBudget("")
	gasBudget, _ := new(big.Int).SetString(gasBudgetStr, 10)

	// 直接获取凑好 USDC 的转账 PTB
	ptb, err := BuildSuiTransferPTB(ctx, client, from, to, usdcCoinType, uint64(amountInt64))
	if err != nil {
		return nil, err
	}

	txBase64, err := BuildSuiSponsoredTransaction(ctx, client, ptb, from, to, gasBudget.Uint64())
	if err != nil {
		return nil, err
	}

	suiSignatureBase64, err := signManagedSuiTransaction(s, txBase64, &signer.SignRequest{
		UID:           uid,
		SignMode:      "swap",
		To:            to,
		TokenContract: usdcCoinType,
		// TODO<robin>: amountUSD 要转成 wei 单位和格式
		AmountWei: strconv.FormatUint(amountUSD, 10),
	})
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		TxBase64:  txBase64,
		Signature: suiSignatureBase64,
	}, nil
}

// BuildSuiTransferPTB 封装 Sui 凑代币和组装转账 PTB 的繁琐逻辑
// 它会自动从 owner 钱包拉取足够的 coinType 代币，凑齐 amount，并向 recipient 生成 Pay 指令
func BuildSuiTransferPTB(
	ctx context.Context,
	client suiclient.ISuiAPI,
	ownerHex, recipientHex, coinType string,
	amount uint64,
) (*suitypes.ProgrammableTransactionBuilder, error) {

	recipientAddrObj, err := suitypes.NewAddressFromHex(recipientHex)
	if err != nil {
		return nil, err
	}

	// 1. 获取用户的代币来构造输入 ObjectRefs
	var inputCoinRefs []*suitypes.ObjectRef
	userCoins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    ownerHex,
		CoinType: coinType,
		Limit:    50, // 注意：如果用户碎片硬币极多，可能需要翻页，这里暂保持现状
	})
	if err != nil {
		return nil, err
	}

	amountNeeded := new(big.Int).SetUint64(amount)
	amountGathered := big.NewInt(0)
	for _, c := range userCoins.Data {
		coinAmt, ok := new(big.Int).SetString(strings.TrimSpace(c.Balance), 10)
		if ok && coinAmt.Sign() > 0 {
			objID, _ := suitypes.NewAddressFromHex(c.CoinObjectId)
			digest, _ := lib.NewBase58(c.Digest)
			var v uint64
			fmt.Sscanf(c.Version, "%d", &v)

			inputCoinRefs = append(inputCoinRefs, &suitypes.ObjectRef{
				ObjectId: *objID,
				Version:  suitypes.SequenceNumber(v),
				Digest:   *digest,
			})
			amountGathered.Add(amountGathered, coinAmt)
			if amountGathered.Cmp(amountNeeded) >= 0 {
				break
			}
		}
	}

	if amountGathered.Cmp(amountNeeded) < 0 {
		return nil, errors.New("insufficient token balance to build transaction")
	}

	// 2. 构造交易 PTB
	ptb := suitypes.NewProgrammableTransactionBuilder()
	ptb.Pay(inputCoinRefs, []suitypes.SuiAddress{*recipientAddrObj}, []uint64{amount})

	return ptb, nil
}

// BuildSuiSponsoredTransaction 封装 Sui 代付交易的公共构造逻辑
// 业务层只需提供构造好的 PTB 对象，此函数负责注入 Sponsor 的 Gas 和正确的 GasOwner
func BuildSuiSponsoredTransaction(
	ctx context.Context,
	client suiclient.ISuiAPI,
	ptb *suitypes.ProgrammableTransactionBuilder, // 业务层构造好的指令 (如 Pay, MoveCall)
	userAddrHex, sponsorAddrHex string,
	gasBudget uint64,
) (string, error) { // 返回 base64 编码的 txBytes
	pt := ptb.Finish()
	return BuildSuiSponsoredTransactionFromKind(
		ctx,
		client,
		suitypes.TransactionKind{ProgrammableTransaction: &pt},
		suitypes.TransactionExpiration{None: &lib.EmptyEnum{}},
		userAddrHex,
		sponsorAddrHex,
		gasBudget,
	)
}

func BuildSuiSponsoredTransactionFromKind(
	ctx context.Context,
	client suiclient.ISuiAPI,
	kind suitypes.TransactionKind,
	expiration suitypes.TransactionExpiration,
	userAddrHex, sponsorAddrHex string,
	gasBudget uint64,
) (string, error) {
	// 1. 获取 GasPrice
	gasPrice, _ := client.SuiXGetReferenceGasPrice(ctx)
	if gasPrice <= 0 {
		gasPrice = 1000 // fallback
	}

	// 2. 获取 Sponsor 地址下的 SUI Coin 作为 Payment
	sponsorCoins, err := client.SuiXGetCoins(ctx, suimodels.SuiXGetCoinsRequest{
		Owner:    sponsorAddrHex,
		CoinType: "0x2::sui::SUI",
		Limit:    5,
	})
	if err != nil || len(sponsorCoins.Data) == 0 {
		return "", fmt.Errorf("failed to fetch sponsor SUI coins for gas payment: %w", err)
	}

	var sponsorGasRef *suitypes.ObjectRef
	for _, c := range sponsorCoins.Data {
		b, _ := new(big.Int).SetString(strings.TrimSpace(c.Balance), 10)
		if b.Sign() > 0 {
			objID, _ := suitypes.NewAddressFromHex(c.CoinObjectId)
			digest, _ := lib.NewBase58(c.Digest)
			var v uint64
			fmt.Sscanf(c.Version, "%d", &v)
			seq := suitypes.SequenceNumber(v)

			sponsorGasRef = &suitypes.ObjectRef{
				ObjectId: *objID,
				Version:  seq,
				Digest:   *digest,
			}
			break
		}
	}
	if sponsorGasRef == nil {
		return "", errors.New("sponsor does not have any SUI coins with balance > 0")
	}

	userAddr, _ := suitypes.NewAddressFromHex(userAddrHex)
	sponsorAddr, _ := suitypes.NewAddressFromHex(sponsorAddrHex)

	txDataObj := suitypes.TransactionData{
		V1: &suitypes.TransactionDataV1{
			Kind:   kind,
			Sender: *userAddr,
			GasData: suitypes.GasData{
				Payment: []*suitypes.ObjectRef{sponsorGasRef},
				Owner:   *sponsorAddr, // 强制指定为 Sponsor 的地址
				Price:   gasPrice,
				Budget:  gasBudget,
			},
			Expiration: expiration,
		},
	}

	bcsBytes, err := bcs.Marshal(txDataObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal transaction data: %w", err)
	}

	txBase64 := base64.StdEncoding.EncodeToString(bcsBytes)
	return txBase64, nil
}

// ----------------------------------------------------------------------------
// EVM Adapter (EIP-2612 permit 代付)
// ----------------------------------------------------------------------------

// EVMUSDCContracts EVM 各网络 USDC 合约地址
var EVMUSDCContracts = map[string]string{
	"sepolia":   "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
	"testnet":   "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
	"mainnet":   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
	"ethereum":  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // Ethereum mainnet
	"base":      "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	"arbitrum":  "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
	"optimism":  "0x0b2C02Bd0c7B2B5d2dA08d6EFdcFfa2C6ef40A65",
	"polygon":   "0x2791Bca1f2de4661ED88A30C99a7a9449Aa84174",
	"bsc":       "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
	"avalanche": "0xA7D8d9ef8D56cc95e3B8B59BEBd3D12c111ce51f",
	"linea":     "0x176211869cA2b568f2A7D4EE6B351DFF2fEcCD63",
	"zksync":    "0x3355df6D4c9C3035724Fd0e3914dE96A5a83aaf4",
}

func getEVMUSDCContract(network string) string {
	network = strings.ToLower(network)
	if addr, ok := EVMUSDCContracts[network]; ok {
		return addr
	}
	// 不再默认返回 mainnet，而是返回空字符串，让调用方能够检测到错误
	// 这样可以避免在错误的网络上查询 USDC 余额
	return ""
}

type EVMSponsorAdapter struct{}

func (a *EVMSponsorAdapter) GetBalances(ctx context.Context, network, address string) (uint64, uint64, error) {
	chain := evmNetworkToChain(network)

	// 获取主 RPC URL
	rpcURL, err := chainRPCURL(chain)
	if err != nil {
		return 0, 0, err
	}

	// 尝试从主 RPC 节点查询
	native, usdc, err := a.getBalancesFromRPC(ctx, rpcURL, network, address)
	if err == nil {
		return native, usdc, nil
	}

	// 主节点失败，尝试备用 RPC 节点
	fmt.Printf("[EVMGetBalances] Primary RPC failed: %v, trying backup nodes...\n", err)
	backupRPCs := a.getBackupRPCURLs(chain)
	for i, backupRPC := range backupRPCs {
		fmt.Printf("[EVMGetBalances] Trying backup RPC %d: %s\n", i+1, backupRPC)
		native, usdc, err := a.getBalancesFromRPC(ctx, backupRPC, network, address)
		if err == nil {
			fmt.Printf("[EVMGetBalances] Backup RPC %d succeeded\n", i+1)
			return native, usdc, nil
		}
		fmt.Printf("[EVMGetBalances] Backup RPC %d failed: %v\n", i+1, err)
	}

	return 0, 0, fmt.Errorf("all RPC nodes failed to get balances for address %s", address)
}

// getBalancesFromRPC 从指定的 RPC 节点查询余额
func (a *EVMSponsorAdapter) getBalancesFromRPC(ctx context.Context, rpcURL, network, address string) (uint64, uint64, error) {
	// 查询原生 ETH 余额
	nativeHex, err := evmCallRPC(rpcURL, "eth_getBalance", []any{address, "latest"})
	if err != nil {
		return 0, 0, fmt.Errorf("eth_getBalance failed: %w", err)
	}
	nativeBig, _ := new(big.Int).SetString(strings.TrimPrefix(nativeHex, "0x"), 16)
	if nativeBig == nil {
		nativeBig = big.NewInt(0)
	}
	// 代付触发条件：ETH 余额低于 0.001 ETH (1e15 wei) 视为"无 gas"，返回 0
	// 这样 SubmitAndBroadcast 里 nativeBal == 0 才会触发代付
	const gasThresholdWei = 1_000_000_000_000_000 // 0.001 ETH
	var native uint64
	if nativeBig.IsInt64() && nativeBig.Int64() >= gasThresholdWei {
		native = uint64(nativeBig.Int64()) // 有足够 gas，不触发代付
	}
	// native == 0 表示余额低于阈值，触发代付逻辑

	// 查询 USDC 余额：balanceOf(address)
	usdcContract := getEVMUSDCContract(network)
	if usdcContract == "" {
		return 0, 0, fmt.Errorf("USDC contract not configured for network: %s", network)
	}
	fmt.Printf("[EVMGetBalances] Querying USDC contract: %s on network: %s\n", usdcContract, network)

	selector := []byte{0x70, 0xa0, 0x82, 0x31} // keccak256("balanceOf(address)")[:4]
	addrPadded := ethcommon.LeftPadBytes(ethcommon.HexToAddress(address).Bytes(), 32)
	callData := "0x" + fmt.Sprintf("%x", append(selector, addrPadded...))
	fmt.Printf("[EVMGetBalances] Calling balanceOf with data: %s\n", callData)

	resultHex, err := evmCallRPC(rpcURL, "eth_call", []any{
		map[string]string{"to": usdcContract, "data": callData},
		"latest",
	})
	if err != nil {
		return 0, 0, fmt.Errorf("USDC balanceOf query failed: %w", err)
	}

	fmt.Printf("[EVMGetBalances] USDC balanceOf raw response: %s\n", resultHex)

	usdcBig, _ := new(big.Int).SetString(strings.TrimPrefix(resultHex, "0x"), 16)
	if usdcBig == nil {
		return 0, 0, fmt.Errorf("invalid USDC balance response: %s", resultHex)
	}

	usdc := usdcBig.Uint64()

	// 打印查询结果
	fmt.Printf("[EVMGetBalances] address=%s network=%s nativeBalance(wei)=%d usdcBalance(microUSDC)=%d\n",
		address, network, native, usdc)

	return native, usdc, nil
}

// getBackupRPCURLs 获取指定链的备用 RPC 节点列表
func (a *EVMSponsorAdapter) getBackupRPCURLs(chain string) []string {
	chain = strings.ToLower(chain)
	backupMap := map[string][]string{
		"ethereum": {
			"https://eth.publicrpc.com",
			"https://ethereum-rpc.publicnode.com",
			"https://1rpc.io/eth",
		},
		"sepolia": {
			"https://sepolia.publicrpc.com",
			"https://sepolia-rpc.publicnode.com",
		},
		"base": {
			"https://base-rpc.publicnode.com",
			"https://base.publicrpc.com",
		},
		"arbitrum": {
			"https://arbitrum-one-rpc.publicnode.com",
			"https://arbitrum.publicrpc.com",
		},
		"optimism": {
			"https://optimism-rpc.publicnode.com",
			"https://optimism.publicrpc.com",
		},
		"polygon": {
			"https://polygon-rpc.com",
			"https://polygon-pokt.nodies.app",
		},
		"bsc": {
			"https://bsc-rpc.publicnode.com",
			"https://bsc.publicrpc.com",
		},
		"avalanche": {
			"https://avalanche-c-chain-rpc.publicnode.com",
			"https://avax-pokt.nodies.app",
		},
		"linea": {
			"https://linea-rpc.publicnode.com",
			"https://linea.decubate.com",
		},
		"zksync": {
			"https://mainnet.era.zksync.io",
			"https://zksync-rpc.publicnode.com",
		},
	}

	if urls, ok := backupMap[chain]; ok {
		return urls
	}
	return []string{}
}

// BuildAndSignUSDC 实现 EIP-2612 permit 签名并调用后端代付接口
// 对于 EVM，"构建并签名 USDC 支付" 等价于：
//  1. 向后端估算需要多少 USDC（priceUSD 已由调用方传入）
//  2. 用户对 Permit 结构体做 EIP-712 链下签名
//  3. 调用 /gas-sponsor/eip2612/permit，由 sponsor 上链
//
// 返回的 BuildResult.TxBase64 = gas_tx_hash（ETH 转账 hash），Signature = permit v+r+s 摘要
func (a *EVMSponsorAdapter) BuildAndSignUSDC(ctx context.Context, network, from, to string, amountUSD uint64, uid string) (*BuildResult, error) {
	chain := evmNetworkToChain(network)
	rpcURL, err := chainRPCURL(chain)
	if err != nil {
		return nil, err
	}
	if !ethcommon.IsHexAddress(from) {
		return nil, fmt.Errorf("invalid owner address: %s", from)
	}
	if !ethcommon.IsHexAddress(to) {
		return nil, fmt.Errorf("invalid spender address: %s", to)
	}
	if amountUSD == 0 {
		return nil, errors.New("USDC payment amount must be greater than 0")
	}

	usdcContract := getEVMUSDCContract(network)
	if usdcContract == "" {
		return nil, fmt.Errorf("USDC contract not configured for network: %s", network)
	}

	chainIDBig, err := evmQueryChainID(rpcURL)
	if err != nil {
		return nil, err
	}

	nonce, err := evmQueryPermitNonce(rpcURL, usdcContract, from)
	if err != nil {
		return nil, err
	}

	// 3. 查询 token name：name() selector = 0x06fdde03
	tokenName, err := evmQueryTokenName(rpcURL, usdcContract)
	if err != nil {
		tokenName = "USD Coin" // fallback
	}

	// 4. 构造 EIP-712 Permit 签名
	// 使用链上最新区块时间戳来计算过期时间，避免本机时间漂移导致 "permit is expired"
	deadline, err := evmBuildPermitDeadline(rpcURL, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	permitValue := new(big.Int).SetUint64(amountUSD)
	ownerAddr := ethcommon.HexToAddress(from)
	spenderAddr := ethcommon.HexToAddress(to)
	tokenAddr := ethcommon.HexToAddress(usdcContract)

	// 获取 signer 的私钥材料，通过 raw_hash 签名方式完成 EIP-712
	fmt.Printf("[BuildAndSignUSDC] Starting EIP-712 signing: uid=%s, from=%s, to=%s\n", uid, from, to)
	v, r, s, err := signEIP712PermitWithName(
		uid, chain, chainIDBig, tokenAddr, tokenName,
		ownerAddr, spenderAddr,
		permitValue, nonce, big.NewInt(deadline),
	)
	if err != nil {
		fmt.Printf("[BuildAndSignUSDC] EIP-712 signing failed: %v\n", err)
		return nil, fmt.Errorf("EIP-712 permit sign failed: %w", err)
	}
	fmt.Printf("[BuildAndSignUSDC] EIP-712 signing succeeded: v=%d\n", v)

	// 5. 提交 permit 到后端
	client := sponsor.NewClient(getSponsorBaseURL())
	gasTxHash, err := client.SubmitEIP2612Permit(sponsor.EIP2612PermitRequest{
		Chain:    chain,
		Owner:    from,
		Value:    permitValue.String(),
		Deadline: deadline,
		V:        v,
		R:        r,
		S:        s,
	})
	if err != nil {
		return nil, fmt.Errorf("eip2612 permit submission failed: %w", err)
	}

	return &BuildResult{
		TxBase64:  gasTxHash, // gas_tx_hash，用于后续等待确认
		Signature: fmt.Sprintf("v=%d,r=%s,s=%s", v, r, s),
	}, nil
}

// signEIP712PermitWithName 完整的 EIP-712 Permit 签名实现，通过 sandbox signer raw_hash 模式完成
func signEIP712PermitWithName(
	uid string,
	chain string,
	chainID *big.Int,
	tokenAddr ethcommon.Address,
	tokenName string,
	owner, spender ethcommon.Address,
	value, nonce, deadline *big.Int,
) (uint8, string, string, error) {
	s, _, _, err := GetActiveSignerContext()
	if err != nil {
		return 0, "", "", err
	}

	digest := buildEIP712PermitDigest(chainID, tokenAddr, tokenName, owner, spender, value, nonce, deadline)
	digestHex := "0x" + fmt.Sprintf("%x", digest.Bytes())

	signReq := &signer.SignRequest{
		UID:             uid,
		Chain:           chain,
		SignMode:        "raw_hash",
		TxPayloadHex:    digestHex,
		ConfirmedByUser: true,
	}

	if err := PopulateSigningShares(signReq); err != nil {
		return 0, "", "", err
	}

	signRes, err := s.Sign(signReq)
	if err != nil {
		return 0, "", "", fmt.Errorf("raw_hash sign failed: %w", err)
	}

	return splitEIP2612Signature(signRes.SignatureHex)
}

func evmQueryChainID(rpcURL string) (*big.Int, error) {
	chainIDHex, err := evmCallRPC(rpcURL, "eth_chainId", []any{})
	if err != nil {
		return nil, fmt.Errorf("eth_chainId failed: %w", err)
	}
	chainIDBig, _ := new(big.Int).SetString(strings.TrimPrefix(chainIDHex, "0x"), 16)
	if chainIDBig == nil {
		return nil, fmt.Errorf("invalid chainId: %s", chainIDHex)
	}
	return chainIDBig, nil
}

func evmQueryPermitNonce(rpcURL, tokenAddr, ownerAddr string) (*big.Int, error) {
	nonceSelector := []byte{0x7e, 0xce, 0xbe, 0x00} // nonces(address)
	addrPadded := ethcommon.LeftPadBytes(ethcommon.HexToAddress(ownerAddr).Bytes(), 32)
	nonceCallData := "0x" + fmt.Sprintf("%x", append(nonceSelector, addrPadded...))
	nonceHex, err := evmCallRPC(rpcURL, "eth_call", []any{
		map[string]string{"to": tokenAddr, "data": nonceCallData},
		"latest",
	})
	if err != nil {
		return nil, fmt.Errorf("nonces() call failed: %w", err)
	}
	nonce, _ := new(big.Int).SetString(strings.TrimPrefix(nonceHex, "0x"), 16)
	if nonce == nil {
		return nil, fmt.Errorf("invalid nonce response: %s", nonceHex)
	}
	return nonce, nil
}

func evmBuildPermitDeadline(rpcURL string, ttl time.Duration) (int64, error) {
	chainNow, err := evmQueryLatestBlockTimestamp(rpcURL)
	if err != nil {
		return 0, err
	}
	return chainNow + int64(ttl/time.Second), nil
}

func evmQueryLatestBlockTimestamp(rpcURL string) (int64, error) {
	type blockResult struct {
		Timestamp string `json:"timestamp"`
	}
	type blockResp struct {
		Result *blockResult `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getBlockByNumber",
		"params":  []any{"latest", false},
		"id":      1,
	})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("eth_getBlockByNumber failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read eth_getBlockByNumber response failed: %w", err)
	}

	var r blockResp
	if err := json.Unmarshal(rawBody, &r); err != nil {
		return 0, fmt.Errorf("decode eth_getBlockByNumber response failed: %w", err)
	}
	if r.Error != nil {
		return 0, fmt.Errorf("eth_getBlockByNumber rpc error: %s", r.Error.Message)
	}
	if r.Result == nil || strings.TrimSpace(r.Result.Timestamp) == "" {
		return 0, errors.New("eth_getBlockByNumber returned empty timestamp")
	}

	ts, ok := new(big.Int).SetString(strings.TrimPrefix(r.Result.Timestamp, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("invalid block timestamp: %s", r.Result.Timestamp)
	}
	if !ts.IsInt64() {
		return 0, fmt.Errorf("block timestamp too large: %s", r.Result.Timestamp)
	}
	return ts.Int64(), nil
}

func buildEIP712PermitDigest(
	chainID *big.Int,
	tokenAddr ethcommon.Address,
	tokenName string,
	owner, spender ethcommon.Address,
	value, nonce, deadline *big.Int,
) ethcommon.Hash {
	domainSeparator := buildEIP712DomainSeparator(chainID, tokenAddr, tokenName)
	structHash := buildEIP712PermitStructHash(owner, spender, value, nonce, deadline)
	return crypto.Keccak256Hash(
		[]byte{0x19, 0x01},
		domainSeparator.Bytes(),
		structHash.Bytes(),
	)
}

func buildEIP712DomainSeparator(chainID *big.Int, tokenAddr ethcommon.Address, tokenName string) ethcommon.Hash {
	domainTypeHash := crypto.Keccak256Hash([]byte(
		"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
	))
	nameHash := crypto.Keccak256Hash([]byte(tokenName))
	versionHash := crypto.Keccak256Hash([]byte("2"))
	domainEncoded := make([]byte, 5*32)
	copy(domainEncoded[0:32], domainTypeHash.Bytes())
	copy(domainEncoded[32:64], nameHash.Bytes())
	copy(domainEncoded[64:96], versionHash.Bytes())
	copy(domainEncoded[96:128], ethcommon.LeftPadBytes(chainID.Bytes(), 32))
	copy(domainEncoded[128:160], ethcommon.LeftPadBytes(tokenAddr.Bytes(), 32))
	return crypto.Keccak256Hash(domainEncoded)
}

func buildEIP712PermitStructHash(
	owner, spender ethcommon.Address,
	value, nonce, deadline *big.Int,
) ethcommon.Hash {
	permitTypeHash := crypto.Keccak256Hash([]byte(
		"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
	))
	permitEncoded := make([]byte, 6*32)
	copy(permitEncoded[0:32], permitTypeHash.Bytes())
	copy(permitEncoded[32:64], ethcommon.LeftPadBytes(owner.Bytes(), 32))
	copy(permitEncoded[64:96], ethcommon.LeftPadBytes(spender.Bytes(), 32))
	copy(permitEncoded[96:128], ethcommon.LeftPadBytes(value.Bytes(), 32))
	copy(permitEncoded[128:160], ethcommon.LeftPadBytes(nonce.Bytes(), 32))
	copy(permitEncoded[160:192], ethcommon.LeftPadBytes(deadline.Bytes(), 32))
	return crypto.Keccak256Hash(permitEncoded)
}

func splitEIP2612Signature(signatureHex string) (uint8, string, string, error) {
	sigBytes, err := DecodeHex(signatureHex)
	if err != nil {
		return 0, "", "", fmt.Errorf("decode signature hex failed: %w", err)
	}
	if len(sigBytes) != 65 {
		return 0, "", "", fmt.Errorf("invalid signature bytes: len=%d, expected 65", len(sigBytes))
	}

	// go-ethereum 返回 v=0/1，EIP-2612 合约期望 v=27/28
	v := sigBytes[64]
	if v < 27 {
		v += 27
	}
	r := "0x" + fmt.Sprintf("%064x", sigBytes[:32])
	s := "0x" + fmt.Sprintf("%064x", sigBytes[32:64])
	return v, r, s, nil
}

// evmNetworkToChain 将 network 名映射到 chain 名（用于 chainRPCURL 查询）
func evmNetworkToChain(network string) string {
	switch strings.ToLower(network) {
	case "sepolia":
		return "sepolia"
	case "mainnet", "ethereum":
		return "ethereum"
	default:
		return network
	}
}

// evmCallRPC 向 EVM RPC 发起 eth_call / eth_getBalance 等调用，返回 hex 字符串结果
// 包含自动重试逻辑处理网络瞬间故障
func evmCallRPC(rpcURL, method string, params []any) (string, error) {
	type rpcReq struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
		ID      int    `json:"id"`
	}
	type rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	maxRetries := 3
	retryDelays := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})

		// 设置超时的 HTTP 客户端
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))

		if err != nil {
			lastErr = fmt.Errorf("attempt %d: post failed: %w", attempt+1, err)
			if attempt < maxRetries-1 {
				fmt.Printf("[evmCallRPC] %v, retrying in %v...\n", lastErr, retryDelays[attempt])
				time.Sleep(retryDelays[attempt])
			}
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if readErr != nil {
			lastErr = fmt.Errorf("attempt %d: read body failed: %w", attempt+1, readErr)
			if attempt < maxRetries-1 {
				fmt.Printf("[evmCallRPC] %v, retrying in %v...\n", lastErr, retryDelays[attempt])
				time.Sleep(retryDelays[attempt])
			}
			continue
		}

		var r rpcResp
		if err := json.Unmarshal(respBody, &r); err != nil {
			lastErr = fmt.Errorf("attempt %d: unmarshal json failed: %w", attempt+1, err)
			if attempt < maxRetries-1 {
				fmt.Printf("[evmCallRPC] %v, retrying in %v...\n", lastErr, retryDelays[attempt])
				time.Sleep(retryDelays[attempt])
			}
			continue
		}

		if r.Error != nil {
			lastErr = fmt.Errorf("rpc error: %s", r.Error.Message)
			// 某些错误不应重试
			if strings.Contains(r.Error.Message, "invalid") || strings.Contains(r.Error.Message, "parse") {
				return "", lastErr
			}
			if attempt < maxRetries-1 {
				fmt.Printf("[evmCallRPC] %v, retrying in %v...\n", lastErr, retryDelays[attempt])
				time.Sleep(retryDelays[attempt])
			}
			continue
		}

		return r.Result, nil
	}

	return "", lastErr
}

// evmQueryTokenName 查询 ERC20 token name()
func evmQueryTokenName(rpcURL, tokenAddr string) (string, error) {
	// selector: keccak256("name()") = 0x06fdde03
	resultHex, err := evmCallRPC(rpcURL, "eth_call", []any{
		map[string]string{"to": tokenAddr, "data": "0x06fdde03"},
		"latest",
	})
	if err != nil {
		return "", err
	}
	raw, err := DecodeHex(resultHex)
	if err != nil || len(raw) < 96 {
		return "", fmt.Errorf("name() response too short")
	}
	strLen := new(big.Int).SetBytes(raw[32:64]).Int64()
	if int64(len(raw)) < 64+strLen {
		return "", fmt.Errorf("name() response truncated")
	}
	return string(raw[64 : 64+strLen]), nil
}

// httpPost 简单的 HTTP POST 辅助，返回响应 body bytes
func httpPost(url, contentType string, body []byte) ([]byte, error) {
	resp, err := (&http.Client{}).Post(url, contentType, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
