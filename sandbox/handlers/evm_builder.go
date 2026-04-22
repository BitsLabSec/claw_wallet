package handlers

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sandbox/internals/assets"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// 属于helps函数
// TODO:后续可以将此类代码分开
type EvmStructuredBuild struct {
	BuilderKind   string
	Recipient     string
	TokenContract string
	TxTo          string
	AmountWei     string
	Value         *big.Int
	Data          []byte
	Nonce         uint64
	GasPrice      *big.Int
	GasLimit      uint64
	ChainID       *big.Int
	TxPayloadHex  string
}

func buildStructuredEVMSigningPayload(chain, from string, req *signer.SignRequest) (*EvmStructuredBuild, error) {
	if req == nil {
		return nil, fmt.Errorf("missing sign request")
	}
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("structured builder is not available for chain %q", chain)
	}
	if !common.IsHexAddress(from) {
		return nil, fmt.Errorf("invalid sender address %q", from)
	}

	amount, ok := new(big.Int).SetString(strings.TrimSpace(req.AmountWei), 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount_wei")
	}

	builder := &EvmStructuredBuild{
		BuilderKind:   strings.ToLower(strings.TrimSpace(req.BuilderKind)),
		Recipient:     strings.TrimSpace(req.To),
		TokenContract: strings.TrimSpace(req.TokenContract),
		AmountWei:     amount.String(),
		Value:         big.NewInt(0),
		GasPrice:      big.NewInt(0),
		ChainID:       big.NewInt(0),
	}

	if !common.IsHexAddress(builder.Recipient) {
		return nil, fmt.Errorf("invalid recipient address %q", builder.Recipient)
	}

	switch builder.BuilderKind {
	case "native_transfer":
		if data := strings.TrimSpace(req.Data); data != "" && data != "0x" {
			return nil, fmt.Errorf("native_transfer only supports empty calldata")
		}
		builder.TxTo = builder.Recipient
		builder.Value = amount
		builder.Data = nil
	case "erc20_transfer":
		if !common.IsHexAddress(builder.TokenContract) {
			return nil, fmt.Errorf("invalid token contract %q", builder.TokenContract)
		}
		if data := strings.TrimSpace(req.Data); data != "" && data != "0x" {
			return nil, fmt.Errorf("erc20_transfer calldata is built by the sandbox and must not be provided externally")
		}
		builder.TxTo = builder.TokenContract
		builder.Value = big.NewInt(0)
		builder.Data = buildERC20TransferCalldata(builder.Recipient, amount)
	default:
		return nil, fmt.Errorf("unsupported EVM builder_kind %q", req.BuilderKind)
	}

	chainID, err := evmRPCBigInt(chain, "eth_chainId", []interface{}{})
	if err != nil {
		return nil, err
	}
	builder.ChainID = chainID

	nonce, err := EvmRPCUint64(chain, "eth_getTransactionCount", []interface{}{from, "pending"})
	if err != nil {
		return nil, err
	}
	builder.Nonce = nonce

	gasPrice, err := evmRPCBigInt(chain, "eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, err
	}
	builder.GasPrice = gasPrice

	estimateArgs := map[string]string{
		"from":  from,
		"to":    builder.TxTo,
		"value": hexutil.EncodeBig(builder.Value),
		"data":  "0x" + hex.EncodeToString(builder.Data),
	}
	gasLimit, err := EvmRPCUint64(chain, "eth_estimateGas", []interface{}{estimateArgs})
	if err != nil {
		return nil, err
	}
	builder.GasLimit = gasLimit

	payload, err := encodeLegacyEVMSigningPayload(builder.Nonce, builder.GasPrice, builder.GasLimit, builder.TxTo, builder.Value, builder.Data, builder.ChainID)
	if err != nil {
		return nil, err
	}
	builder.TxPayloadHex = "0x" + hex.EncodeToString(payload)
	return builder, nil
}

func buildERC20TransferCalldata(recipient string, amount *big.Int) []byte {
	methodID, _ := hex.DecodeString("a9059cbb")
	recipientBytes := common.HexToAddress(recipient).Bytes()
	amountBytes := amount.FillBytes(make([]byte, 32))

	data := make([]byte, 0, 4+32+32)
	data = append(data, methodID...)
	data = append(data, common.LeftPadBytes(recipientBytes, 32)...)
	data = append(data, amountBytes...)
	return data
}

func encodeLegacyEVMSigningPayload(nonce uint64, gasPrice *big.Int, gasLimit uint64, to string, value *big.Int, data []byte, chainID *big.Int) ([]byte, error) {
	if !common.IsHexAddress(to) {
		return nil, fmt.Errorf("invalid transaction target %q", to)
	}
	if gasPrice == nil || value == nil || chainID == nil {
		return nil, fmt.Errorf("missing transaction fields for signing payload")
	}
	payload, err := rlp.EncodeToBytes([]interface{}{
		nonce,
		gasPrice,
		gasLimit,
		common.HexToAddress(to).Bytes(),
		value,
		data,
		chainID,
		uint(0),
		uint(0),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode signing payload: %w", err)
	}
	return payload, nil
}

func AssembleSignedLegacyEVMTransaction(build *EvmStructuredBuild, signatureHex string) (string, error) {
	if build == nil {
		return "", fmt.Errorf("missing structured build")
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

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := new(big.Int).Mul(build.ChainID, big.NewInt(2))
	v.Add(v, big.NewInt(int64(35+sig[64])))

	rawTx, err := rlp.EncodeToBytes([]interface{}{
		build.Nonce,
		build.GasPrice,
		build.GasLimit,
		common.HexToAddress(build.TxTo).Bytes(),
		build.Value,
		build.Data,
		v,
		r,
		s,
	})
	if err != nil {
		return "", fmt.Errorf("failed to assemble signed transaction: %w", err)
	}
	return "0x" + hex.EncodeToString(rawTx), nil
}

// SimulateEVMCall runs eth_call to simulate the tx; returns error if it would revert.
func SimulateEVMCall(chain, from, to string, value *big.Int, data []byte) error {
	if value == nil {
		value = new(big.Int)
	}
	call := map[string]string{
		"from":  from,
		"to":    to,
		"value": hexutil.EncodeBig(value),
		"data":  "0x" + hex.EncodeToString(data),
	}
	var result string
	if err := callChainRPC(chain, "eth_call", []interface{}{call, "latest"}, &result); err != nil {
		return fmt.Errorf("simulation failed (tx would revert): %w", err)
	}
	return nil
}

func EvmRPCUint64(chain, method string, params []interface{}) (uint64, error) {
	var raw string
	if err := callChainRPC(chain, method, params, &raw); err != nil {
		return 0, err
	}
	value, err := hexutil.DecodeUint64(raw)
	if err != nil {
		return 0, fmt.Errorf("%s returned invalid quantity %q: %w", method, raw, err)
	}
	return value, nil
}

func evmRPCBigInt(chain, method string, params []interface{}) (*big.Int, error) {
	var raw string
	if err := callChainRPC(chain, method, params, &raw); err != nil {
		return nil, err
	}
	value, err := hexutil.DecodeBig(raw)
	if err != nil {
		return nil, fmt.Errorf("%s returned invalid quantity %q: %w", method, raw, err)
	}
	return value, nil
}

func callChainRPC(chain, method string, params []interface{}, result interface{}) error {
	chain = strings.ToLower(strings.TrimSpace(chain))
	rpcURLs := assets.RPCProxyURLs(chain)
	if len(rpcURLs) == 0 {
		rpcURL := env("CLAY_RPC_"+strings.ToUpper(strings.TrimSpace(chain)), "")
		if rpcURL == "" {
			var ok bool
			rpcURL, ok = chainRPCEndpoints[chain]
			if !ok {
				return fmt.Errorf("unsupported chain %q", chain)
			}
		}
		rpcURLs = []string{rpcURL}
	}

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return fmt.Errorf("failed to encode RPC request: %w", err)
	}

	resp, rpcURL, err := doRPCProxyRequest(rpcURLs, body, rpcMethodAllowsFallback(method))
	if err != nil {
		return fmt.Errorf("%s RPC call failed via %s: %w", chain, rpcURL, utils.SanitizeError(err))
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s RPC %s failed: %s", chain, method, strings.TrimSpace(string(data)))
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("failed to decode RPC response: %w", err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s RPC %s error %d: %s", chain, method, envelope.Error.Code, envelope.Error.Message)
	}
	if len(envelope.Result) == 0 {
		return fmt.Errorf("%s RPC %s returned no result", chain, method)
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("failed to decode RPC result for %s: %w", method, err)
	}
	return nil
}

func encodeEIP1559EVMSigningPayload(chainID *big.Int, nonce uint64, maxPriorityFeePerGas, maxFeePerGas *big.Int, gasLimit uint64, to string, value *big.Int, data []byte) ([]byte, error) {
	if !common.IsHexAddress(to) {
		return nil, fmt.Errorf("invalid transaction target %q", to)
	}
	if chainID == nil || maxPriorityFeePerGas == nil || maxFeePerGas == nil || value == nil {
		return nil, fmt.Errorf("missing EIP-1559 transaction fields")
	}
	accessList := []interface{}{}
	payload, err := rlp.EncodeToBytes([]interface{}{
		chainID,
		nonce,
		maxPriorityFeePerGas,
		maxFeePerGas,
		gasLimit,
		common.HexToAddress(to).Bytes(),
		value,
		data,
		accessList,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode EIP-1559 signing payload: %w", err)
	}
	return append([]byte{0x02}, payload...), nil
}

func BuildEIP1559EVMTxPayload(chain, from, txTo string, value *big.Int, data []byte, nonce uint64) (*EvmStructuredBuild, error) {
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("EIP-1559 tx builder is not available for chain %q", chain)
	}
	if !common.IsHexAddress(from) {
		return nil, fmt.Errorf("invalid sender address %q", from)
	}
	if !common.IsHexAddress(txTo) {
		return nil, fmt.Errorf("invalid transaction target %q", txTo)
	}
	if value == nil {
		value = big.NewInt(0)
	}

	chainID, err := evmRPCBigInt(chain, "eth_chainId", []interface{}{})
	if err != nil {
		return nil, err
	}

	estimateArgs := map[string]string{
		"from":  from,
		"to":    txTo,
		"value": hexutil.EncodeBig(value),
		"data":  "0x" + hex.EncodeToString(data),
	}
	gasLimit, err := EvmRPCUint64(chain, "eth_estimateGas", []interface{}{estimateArgs})
	if err != nil {
		return nil, err
	}

	maxPriorityFeePerGas, err := evmRPCBigInt(chain, "eth_maxPriorityFeePerGas", []interface{}{})
	if err != nil {
		return nil, fmt.Errorf("eth_maxPriorityFeePerGas not supported (chain may not support EIP-1559): %w", err)
	}

	var baseFee *big.Int
	var blockResult map[string]interface{}
	if err := callChainRPC(chain, "eth_getBlockByNumber", []interface{}{"latest", false}, &blockResult); err != nil {
		return nil, fmt.Errorf("failed to get base fee: %w", err)
	}
	if blockResult != nil {
		if bf, ok := blockResult["baseFeePerGas"].(string); ok && bf != "" {
			baseFee, err = hexutil.DecodeBig(bf)
			if err != nil {
				return nil, fmt.Errorf("invalid baseFeePerGas: %w", err)
			}
		}
	}
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}

	maxFeePerGas := new(big.Int).Mul(baseFee, big.NewInt(2))
	maxFeePerGas.Add(maxFeePerGas, maxPriorityFeePerGas)

	payload, err := encodeEIP1559EVMSigningPayload(chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, txTo, value, data)
	if err != nil {
		return nil, err
	}

	return &EvmStructuredBuild{
		BuilderKind:  "eip1559",
		TxTo:         txTo,
		Value:        value,
		Data:         data,
		Nonce:        nonce,
		GasLimit:     gasLimit,
		ChainID:      chainID,
		TxPayloadHex: "0x" + hex.EncodeToString(payload),
	}, nil
}

func BuildLegacyEVMTxPayload(chain, from, txTo string, value *big.Int, data []byte, nonce uint64) (*EvmStructuredBuild, error) {
	if !signer.IsEVMChain(chain) {
		return nil, fmt.Errorf("legacy tx builder is not available for chain %q", chain)
	}
	if !common.IsHexAddress(from) {
		return nil, fmt.Errorf("invalid sender address %q", from)
	}
	if !common.IsHexAddress(txTo) {
		return nil, fmt.Errorf("invalid transaction target %q", txTo)
	}
	if value == nil {
		value = big.NewInt(0)
	}

	chainID, err := evmRPCBigInt(chain, "eth_chainId", []interface{}{})
	if err != nil {
		return nil, err
	}
	gasPrice, err := evmRPCBigInt(chain, "eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, err
	}

	estimateArgs := map[string]string{
		"from":  from,
		"to":    txTo,
		"value": hexutil.EncodeBig(value),
		"data":  "0x" + hex.EncodeToString(data),
	}
	gasLimit, err := EvmRPCUint64(chain, "eth_estimateGas", []interface{}{estimateArgs})
	if err != nil {
		return nil, err
	}

	payload, err := encodeLegacyEVMSigningPayload(nonce, gasPrice, gasLimit, txTo, value, data, chainID)
	if err != nil {
		return nil, err
	}

	return &EvmStructuredBuild{
		BuilderKind:  "legacy_custom",
		TxTo:         txTo,
		Value:        value,
		Data:         data,
		Nonce:        nonce,
		GasPrice:     gasPrice,
		GasLimit:     gasLimit,
		ChainID:      chainID,
		TxPayloadHex: "0x" + hex.EncodeToString(payload),
	}, nil
}

func evmFunctionSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	sum := h.Sum(nil)
	return sum[:4]
}

func abiWordAddress(addr string) ([]byte, error) {
	addr = strings.TrimSpace(addr)
	if !common.IsHexAddress(addr) {
		return nil, fmt.Errorf("invalid address %q", addr)
	}
	out := make([]byte, 32)
	copy(out[12:], common.HexToAddress(addr).Bytes())
	return out, nil
}

func abiWordBigInt(v *big.Int) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("missing integer value")
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("negative integer is not supported")
	}
	out := make([]byte, 32)
	v.FillBytes(out)
	return out, nil
}

func abiWordUint24(v uint32) ([]byte, error) {
	if v > (1<<24)-1 {
		return nil, fmt.Errorf("uint24 overflow: %d", v)
	}
	return abiWordBigInt(new(big.Int).SetUint64(uint64(v)))
}

func abiWordBool(v bool) []byte {
	out := make([]byte, 32)
	if v {
		out[31] = 1
	}
	return out
}

func buildERC20ApproveCalldata(spender string, amount *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("approve(address,uint256)")
	spenderW, err := abiWordAddress(spender)
	if err != nil {
		return nil, err
	}
	amountW, err := abiWordBigInt(amount)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32+32)
	data = append(data, selector...)
	data = append(data, spenderW...)
	data = append(data, amountW...)
	return data, nil
}

func buildUniswapV3ExactInputSingleCalldata(tokenIn, tokenOut string, fee uint32, recipient string, deadline, amountIn, amountOutMin, sqrtPriceLimitX96 *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))")
	wTokenIn, err := abiWordAddress(tokenIn)
	if err != nil {
		return nil, err
	}
	wTokenOut, err := abiWordAddress(tokenOut)
	if err != nil {
		return nil, err
	}
	wFee, err := abiWordUint24(fee)
	if err != nil {
		return nil, err
	}
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wSqrt, err := abiWordBigInt(sqrtPriceLimitX96)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, 4+8*32)
	data = append(data, selector...)
	data = append(data, wTokenIn...)
	data = append(data, wTokenOut...)
	data = append(data, wFee...)
	data = append(data, wRecipient...)
	data = append(data, wDeadline...)
	data = append(data, wAmountIn...)
	data = append(data, wAmountOutMin...)
	data = append(data, wSqrt...)
	return data, nil
}

const (
	universalRouterCmdV3SwapExactIn byte = 0x00
	universalRouterCmdV2SwapExactIn byte = 0x08
	universalRouterCmdWrapETH       byte = 0x0b
	universalRouterCmdUnwrapWETH    byte = 0x0c
)

func buildUniversalRouterExecuteCalldata(commands []byte, inputs [][]byte, deadline *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("execute(bytes,bytes[],uint256)")
	if deadline == nil || deadline.Sign() <= 0 {
		return nil, fmt.Errorf("invalid deadline")
	}
	commandsEnc := abiEncodeBytes(commands)
	inputsEnc := abiEncodeBytesArray(inputs)
	wCommandsOffset, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(32 * 3)))
	wInputsOffset, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(32*3 + len(commandsEnc))))
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32*3+len(commandsEnc)+len(inputsEnc))
	data = append(data, selector...)
	data = append(data, wCommandsOffset...)
	data = append(data, wInputsOffset...)
	data = append(data, wDeadline...)
	data = append(data, commandsEnc...)
	data = append(data, inputsEnc...)
	return data, nil
}

func encodeUniversalRouterWrapETHInput(recipient string, amount *big.Int) ([]byte, error) {
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wAmount, err := abiWordBigInt(amount)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+32)
	out = append(out, wRecipient...)
	out = append(out, wAmount...)
	return out, nil
}

func encodeUniversalRouterUnwrapWETHInput(recipient string, amountMin *big.Int) ([]byte, error) {
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wAmountMin, err := abiWordBigInt(amountMin)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+32)
	out = append(out, wRecipient...)
	out = append(out, wAmountMin...)
	return out, nil
}

func encodeUniversalRouterV3SwapExactInInput(recipient string, amountIn, amountOutMin *big.Int, path []byte, payerIsUser bool) ([]byte, error) {
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wPathOffset, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(32 * 5)))
	wPayer := abiWordBool(payerIsUser)
	tail := abiEncodeBytes(path)
	out := make([]byte, 0, 32*5+len(tail))
	out = append(out, wRecipient...)
	out = append(out, wAmountIn...)
	out = append(out, wAmountOutMin...)
	out = append(out, wPathOffset...)
	out = append(out, wPayer...)
	out = append(out, tail...)
	return out, nil
}

func encodeUniversalRouterV2SwapExactInInput(recipient string, amountIn, amountOutMin *big.Int, path []string, payerIsUser bool) ([]byte, error) {
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wPathOffset, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(32 * 5)))
	wPayer := abiWordBool(payerIsUser)
	tail, err := abiEncodeAddressArray(path)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32*5+len(tail))
	out = append(out, wRecipient...)
	out = append(out, wAmountIn...)
	out = append(out, wAmountOutMin...)
	out = append(out, wPathOffset...)
	out = append(out, wPayer...)
	out = append(out, tail...)
	return out, nil
}

func abiEncodeBytes(b []byte) []byte {
	lenWord, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(len(b))))
	paddedLen := ((len(b) + 31) / 32) * 32
	out := make([]byte, 0, 32+paddedLen)
	out = append(out, lenWord...)
	out = append(out, b...)
	if pad := paddedLen - len(b); pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

func abiEncodeBytesArray(items [][]byte) []byte {
	n := len(items)
	lenWord, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(n)))
	head := make([]byte, 0, 32*(1+n))
	head = append(head, lenWord...)

	base := 32 * (1 + n)
	offset := base
	offsets := make([][]byte, 0, n)
	encoded := make([][]byte, 0, n)
	for _, it := range items {
		enc := abiEncodeBytes(it)
		encoded = append(encoded, enc)
		offWord, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(offset)))
		offsets = append(offsets, offWord)
		offset += len(enc)
	}
	for _, off := range offsets {
		head = append(head, off...)
	}

	out := make([]byte, 0, len(head)+offset-base)
	out = append(out, head...)
	for _, enc := range encoded {
		out = append(out, enc...)
	}
	return out
}

func abiEncodeAddressArray(items []string) ([]byte, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("address array must not be empty")
	}
	lenWord, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(len(items))))
	out := make([]byte, 0, 32*(1+len(items)))
	out = append(out, lenWord...)
	for _, item := range items {
		word, err := abiWordAddress(item)
		if err != nil {
			return nil, err
		}
		out = append(out, word...)
	}
	return out, nil
}

func buildUniswapV2SwapExactTokensForTokensCalldata(amountIn, amountOutMin *big.Int, path []string, recipient string, deadline *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)")
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wOffset, _ := abiWordBigInt(new(big.Int).SetUint64(32 * 5))
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	tail, err := abiEncodeAddressArray(path)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32*5+len(tail))
	data = append(data, selector...)
	data = append(data, wAmountIn...)
	data = append(data, wAmountOutMin...)
	data = append(data, wOffset...)
	data = append(data, wRecipient...)
	data = append(data, wDeadline...)
	data = append(data, tail...)
	return data, nil
}

func buildUniswapV2SwapExactETHForTokensCalldata(amountOutMin *big.Int, path []string, recipient string, deadline *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("swapExactETHForTokens(uint256,address[],address,uint256)")
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wOffset, _ := abiWordBigInt(new(big.Int).SetUint64(32 * 4))
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	tail, err := abiEncodeAddressArray(path)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32*4+len(tail))
	data = append(data, selector...)
	data = append(data, wAmountOutMin...)
	data = append(data, wOffset...)
	data = append(data, wRecipient...)
	data = append(data, wDeadline...)
	data = append(data, tail...)
	return data, nil
}

func buildUniswapV2SwapExactTokensForETHCalldata(amountIn, amountOutMin *big.Int, path []string, recipient string, deadline *big.Int) ([]byte, error) {
	selector := evmFunctionSelector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)")
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}
	wOffset, _ := abiWordBigInt(new(big.Int).SetUint64(32 * 5))
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	tail, err := abiEncodeAddressArray(path)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32*5+len(tail))
	data = append(data, selector...)
	data = append(data, wAmountIn...)
	data = append(data, wAmountOutMin...)
	data = append(data, wOffset...)
	data = append(data, wRecipient...)
	data = append(data, wDeadline...)
	data = append(data, tail...)
	return data, nil
}

func buildUniswapV3PathSingle(tokenIn string, fee uint32, tokenOut string) ([]byte, error) {
	if !common.IsHexAddress(tokenIn) {
		return nil, fmt.Errorf("invalid token_in %q", tokenIn)
	}
	if !common.IsHexAddress(tokenOut) {
		return nil, fmt.Errorf("invalid token_out %q", tokenOut)
	}
	if fee == 0 || fee > (1<<24)-1 {
		return nil, fmt.Errorf("invalid fee %d", fee)
	}
	in := common.HexToAddress(tokenIn).Bytes()
	out := common.HexToAddress(tokenOut).Bytes()
	fee3 := []byte{byte(fee >> 16), byte(fee >> 8), byte(fee)}
	path := make([]byte, 0, 20+3+20)
	path = append(path, in...)
	path = append(path, fee3...)
	path = append(path, out...)
	return path, nil
}

func validateUniswapV3Path(path []byte) error {
	if len(path) < 20+3+20 {
		return fmt.Errorf("path too short")
	}
	if (len(path)-20)%23 != 0 {
		return fmt.Errorf("invalid path length")
	}
	return nil
}

func buildUniswapV3ExactInputCalldata(path []byte, recipient string, deadline, amountIn, amountOutMin *big.Int) ([]byte, error) {
	if err := validateUniswapV3Path(path); err != nil {
		return nil, err
	}
	selector := evmFunctionSelector("exactInput((bytes,address,uint256,uint256,uint256))")

	wOffset, _ := abiWordBigInt(new(big.Int).SetUint64(uint64(32 * 5)))
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	wDeadline, err := abiWordBigInt(deadline)
	if err != nil {
		return nil, err
	}
	wAmountIn, err := abiWordBigInt(amountIn)
	if err != nil {
		return nil, err
	}
	wAmountOutMin, err := abiWordBigInt(amountOutMin)
	if err != nil {
		return nil, err
	}

	tail := abiEncodeBytes(path)
	data := make([]byte, 0, 4+32*5+len(tail))
	data = append(data, selector...)
	data = append(data, wOffset...)
	data = append(data, wRecipient...)
	data = append(data, wDeadline...)
	data = append(data, wAmountIn...)
	data = append(data, wAmountOutMin...)
	data = append(data, tail...)
	return data, nil
}

func buildUniswapV3MulticallCalldata(calls [][]byte) ([]byte, error) {
	selector := evmFunctionSelector("multicall(bytes[])")
	wOffset, _ := abiWordBigInt(new(big.Int).SetUint64(32))
	tail := abiEncodeBytesArray(calls)
	data := make([]byte, 0, 4+32+len(tail))
	data = append(data, selector...)
	data = append(data, wOffset...)
	data = append(data, tail...)
	return data, nil
}

func buildUniswapV3UnwrapWETH9Calldata(amountMin *big.Int, recipient string) ([]byte, error) {
	selector := evmFunctionSelector("unwrapWETH9(uint256,address)")
	wAmountMin, err := abiWordBigInt(amountMin)
	if err != nil {
		return nil, err
	}
	wRecipient, err := abiWordAddress(recipient)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32+32)
	data = append(data, selector...)
	data = append(data, wAmountMin...)
	data = append(data, wRecipient...)
	return data, nil
}
