package assets

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"sandbox/internals/utils"
)

const (
	monadERC20TransferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	monadLogsChunkSize      = 10_000
	monadLogsMinChunkSize   = 100
	monadNonceProbeStep     = 50_000
	monadBlockNeighborhood  = 3
)

const (
	monadScanPrimaryAPIKeyEnv  = "MONADSCAN_API_KEY"
	monadScanFallbackAPIKeyEnv = "MONADSCAN_FALLBACK_API_KEY"
)

var monadScanAPIBase = "https://api.etherscan.io/v2/api"

type monadNativeTx struct {
	Hash      string
	From      string
	To        string
	Value     *big.Int
	Timestamp time.Time
	Status    string
}

func fetchMonadFastChainData(address string, limit int) ([]Asset, []Transaction, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil, nil, fmt.Errorf("missing monad address")
	}
	if limit <= 0 {
		limit = 100
	}

	history, err := fetchMonadScanHistory(address, limit)
	if err != nil {
		return nil, nil, err
	}

	endpoints := assetRPCURLs("monad")
	if len(endpoints) == 0 {
		return nil, history, fmt.Errorf("monad fast refresh: no rpc endpoints configured")
	}

	assets := make([]Asset, 0, 8)
	if res, err := rpcCallAny(endpoints, "eth_getBalance", []interface{}{address, "latest"}); err == nil {
		if value := monadBigIntFromHex(stringValue(res["result"])); value != nil {
			fValue, _ := new(big.Float).SetInt(value).Float64()
			assets = append(assets, Asset{
				Chain:           "monad",
				ContractAddress: "native",
				Symbol:          getNativeSymbol("monad"),
				BalanceStr:      value.String(),
				Decimals:        18,
				UIBalance:       fValue / 1e18,
				ExplorerURL:     ExplorerAddressURL("monad", address),
			})
		}
	}

	seenContracts := make(map[string]struct{})
	contracts := make([]string, 0, 16)
	state := getSlowChainState("monad", address)
	for _, contract := range state.KnownContracts {
		contract = strings.ToLower(strings.TrimSpace(contract))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seenContracts[contract]; ok {
			continue
		}
		seenContracts[contract] = struct{}{}
		contracts = append(contracts, contract)
	}
	for _, row := range history {
		contract := strings.ToLower(strings.TrimSpace(row.ContractAddress))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seenContracts[contract]; ok {
			continue
		}
		seenContracts[contract] = struct{}{}
		contracts = append(contracts, contract)
	}
	if len(contracts) > standardEVMContractProbeLimit {
		contracts = contracts[:standardEVMContractProbeLimit]
	}

	if len(contracts) > 0 {
		snapshot := append([]string(nil), contracts...)
		updateSlowChainState("monad", address, func(state *slowChainState) {
			state.KnownContracts = snapshot
		})
	}

	for _, contract := range contracts {
		balance, balErr := fetchStandardERC20Balance(endpoints, contract, address)
		if balErr != nil || balance == nil || balance.Sign() <= 0 {
			continue
		}
		symbol, decimals := fetchMonadERC20Meta(endpoints, contract)
		fValue, _ := new(big.Float).SetInt(balance).Float64()
		divisor := 1.0
		for i := 0; i < decimals; i++ {
			divisor *= 10
		}
		assets = append(assets, Asset{
			Chain:           "monad",
			ContractAddress: contract,
			Symbol:          symbol,
			BalanceStr:      balance.String(),
			Decimals:        decimals,
			UIBalance:       fValue / divisor,
			ExplorerURL:     ExplorerTokenURL("monad", contract),
		})
	}

	return assets, history, nil
}

func fetchMonadHistory(endpoints []string, address string, limit int) ([]Transaction, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil, fmt.Errorf("missing monad address")
	}
	if limit <= 0 {
		limit = 50
	}

	rows, err := fetchMonadScanHistory(address, limit)
	if err == nil && len(rows) > 0 {
		return rows, nil
	}

	nativeRows, nativeErr := fetchMonadNativeHistory(endpoints, address, limit)
	tokenRows, tokenErr := fetchMonadERC20History(endpoints, address, limit)

	merged := make([]Transaction, 0, len(nativeRows)+len(tokenRows))
	seen := make(map[string]struct{}, len(nativeRows)+len(tokenRows))
	for _, item := range append(nativeRows, tokenRows...) {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(item.Hash)),
			strings.ToLower(strings.TrimSpace(item.From)),
			strings.ToLower(strings.TrimSpace(item.To)),
			strings.ToLower(strings.TrimSpace(item.ContractAddress)),
			strings.TrimSpace(item.Amount),
			strings.ToLower(strings.TrimSpace(item.Symbol)),
			strings.ToLower(strings.TrimSpace(item.Direction)),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, item)
	}

	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Timestamp.Equal(merged[j].Timestamp) {
			return merged[i].Hash > merged[j].Hash
		}
		return merged[i].Timestamp.After(merged[j].Timestamp)
	})
	if len(merged) > limit {
		merged = merged[:limit]
	}
	if len(merged) == 0 {
		switch {
		case err != nil && nativeErr != nil && tokenErr != nil:
			return nil, fmt.Errorf("monadscan: %v; monad native history: %v; monad erc20 history: %v", err, nativeErr, tokenErr)
		case nativeErr != nil && tokenErr != nil:
			return nil, fmt.Errorf("monad native history: %v; monad erc20 history: %v", nativeErr, tokenErr)
		case nativeErr != nil:
			return nil, nativeErr
		case tokenErr != nil:
			return nil, tokenErr
		}
	}
	return merged, nil
}

type monadScanEnvelope struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

type monadScanNormalTx struct {
	Hash            string `json:"hash"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TimeStamp       string `json:"timeStamp"`
	TxReceiptStatus string `json:"txreceipt_status"`
	IsError         string `json:"isError"`
}

type monadScanTokenTx struct {
	Hash            string `json:"hash"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TimeStamp       string `json:"timeStamp"`
	TokenSymbol     string `json:"tokenSymbol"`
	TokenDecimal    string `json:"tokenDecimal"`
	ContractAddress string `json:"contractAddress"`
}

type monadScanInternalTx struct {
	Hash      string `json:"hash"`
	From      string `json:"from"`
	To        string `json:"to"`
	Value     string `json:"value"`
	TimeStamp string `json:"timeStamp"`
	IsError   string `json:"isError"`
	ErrCode   string `json:"errCode"`
}

func fetchMonadScanHistory(address string, limit int) ([]Transaction, error) {
	items := make([]Transaction, 0, limit*3)

	var normal []monadScanNormalTx
	if err := monadScanGet("txlist", address, limit, &normal); err != nil {
		return nil, err
	}
	for _, row := range normal {
		dir := direction(row.From, row.To, address)
		if dir == "" {
			continue
		}
		items = append(items, Transaction{
			Chain:           "monad",
			Hash:            strings.TrimSpace(row.Hash),
			From:            strings.TrimSpace(row.From),
			To:              strings.TrimSpace(row.To),
			Amount:          formatAmountFromString(row.Value, 18),
			Symbol:          getNativeSymbol("monad"),
			ContractAddress: "native",
			Direction:       dir,
			Timestamp:       monadScanTime(row.TimeStamp),
			Status:          monadScanStatus(row.TxReceiptStatus, row.IsError),
			ExplorerURL:     ExplorerTxURL("monad", row.Hash),
		})
	}

	var internal []monadScanInternalTx
	if err := monadScanGet("txlistinternal", address, limit, &internal); err != nil {
		return nil, err
	}
	for _, row := range internal {
		dir := direction(row.From, row.To, address)
		if dir == "" {
			continue
		}
		items = append(items, Transaction{
			Chain:           "monad",
			Hash:            strings.TrimSpace(row.Hash),
			From:            strings.TrimSpace(row.From),
			To:              strings.TrimSpace(row.To),
			Amount:          formatAmountFromString(row.Value, 18),
			Symbol:          getNativeSymbol("monad"),
			ContractAddress: "native",
			Direction:       dir,
			Timestamp:       monadScanTime(row.TimeStamp),
			Status:          monadScanInternalStatus(row.IsError, row.ErrCode),
			ExplorerURL:     ExplorerTxURL("monad", row.Hash),
		})
	}

	var token []monadScanTokenTx
	if err := monadScanGet("tokentx", address, limit, &token); err != nil {
		return nil, err
	}
	for _, row := range token {
		dir := direction(row.From, row.To, address)
		if dir == "" {
			continue
		}
		items = append(items, Transaction{
			Chain:           "monad",
			Hash:            strings.TrimSpace(row.Hash),
			From:            strings.TrimSpace(row.From),
			To:              strings.TrimSpace(row.To),
			Amount:          formatAmountFromString(row.Value, atoiDefault(strings.TrimSpace(row.TokenDecimal), 18)),
			Symbol:          defaultStr(strings.TrimSpace(row.TokenSymbol), "TOKEN"),
			ContractAddress: strings.TrimSpace(row.ContractAddress),
			Direction:       dir,
			Timestamp:       monadScanTime(row.TimeStamp),
			Status:          "success",
			ExplorerURL:     ExplorerTxURL("monad", row.Hash),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Timestamp.Equal(items[j].Timestamp) {
			return items[i].Hash > items[j].Hash
		}
		return items[i].Timestamp.After(items[j].Timestamp)
	})

	unique := make([]Transaction, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(item.Hash)),
			strings.ToLower(strings.TrimSpace(item.From)),
			strings.ToLower(strings.TrimSpace(item.To)),
			strings.ToLower(strings.TrimSpace(item.ContractAddress)),
			strings.TrimSpace(item.Amount),
			strings.ToLower(strings.TrimSpace(item.Symbol)),
			strings.ToLower(strings.TrimSpace(item.Direction)),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, item)
	}
	if len(unique) > limit {
		unique = unique[:limit]
	}
	return unique, nil
}

func monadScanGet(action, address string, limit int, dest interface{}) error {
	var lastErr error
	for _, apiKey := range monadScanAPIKeys() {
		values := neturl.Values{}
		values.Set("module", "account")
		values.Set("action", action)
		values.Set("chainid", "143")
		values.Set("address", address)
		values.Set("page", "1")
		values.Set("offset", strconv.Itoa(limit))
		values.Set("sort", "desc")
		values.Set("apikey", apiKey)
		if action == "txlist" {
			values.Set("startblock", "0")
			values.Set("endblock", "99999999")
		}
		reqURL := monadScanAPIBase + "?" + values.Encode()
		resp, err := client.Get(reqURL)
		if err != nil {
			lastErr = utils.SanitizeError(err)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= http.StatusBadRequest {
			lastErr = fmt.Errorf("monadscan %s returned %d: %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}

		var envelope monadScanEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			lastErr = err
			continue
		}
		if envelope.Status != "1" {
			msg := strings.Trim(strings.TrimSpace(string(envelope.Result)), "\"")
			if strings.Contains(strings.ToLower(msg), "no transactions found") || strings.Contains(strings.ToLower(msg), "no records found") || msg == "[]" || msg == "" && strings.TrimSpace(string(envelope.Result)) == "[]" {
				return nil
			}
			lastErr = fmt.Errorf("monadscan %s: %s", action, defaultStr(msg, defaultStr(strings.TrimSpace(envelope.Message), "unknown error")))
			continue
		}
		if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
			return nil
		}
		if err := json.Unmarshal(envelope.Result, dest); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("monadscan %s failed without response", action)
	}
	return lastErr
}

func monadScanAPIKeys() []string {
	keys := make([]string, 0, 2)
	for _, envName := range []string{monadScanPrimaryAPIKeyEnv, monadScanFallbackAPIKeyEnv} {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			keys = append(keys, value)
		}
	}
	return keys
}

func fetchMonadNativeHistory(endpoints []string, address string, limit int) ([]Transaction, error) {
	head, err := monadBlockNumber(endpoints)
	if err != nil {
		return nil, err
	}
	latestCount, err := monadTxCount(endpoints, address, "latest")
	if err != nil {
		return nil, err
	}
	if latestCount == 0 {
		updateSlowChainState("monad", address, func(state *slowChainState) {
			state.LastNativeTxCount = 0
		})
		return nil, nil
	}

	minCount := latestCount - limit + 1
	if minCount < 1 {
		minCount = 1
	}
	state := getSlowChainState("monad", address)
	if state.LastNativeTxCount >= latestCount {
		return nil, nil
	}
	if state.LastNativeTxCount > 0 {
		incrementalMin := state.LastNativeTxCount + 1
		if incrementalMin > minCount {
			minCount = incrementalMin
		}
	}
	lowerBound := slowChainLogLowerBound("monad", address, head, endpoints)
	if probed, err := monadFindLowerBound(endpoints, address, head, minCount); err == nil && probed >= 0 {
		lowerBound = probed
	}

	rows := make([]Transaction, 0, latestCount-minCount+1)
	high := head
	for targetCount := latestCount; targetCount >= minCount; targetCount-- {
		blockNumber, err := monadFindFirstBlockWithCountAtLeast(endpoints, address, lowerBound, high, targetCount)
		if err != nil {
			return rows, err
		}
		tx, err := monadFindNativeTxForNonce(endpoints, address, blockNumber, targetCount-1)
		if err != nil {
			high = blockNumber
			continue
		}
		high = blockNumber
		if tx.Value == nil || tx.Value.Sign() <= 0 {
			continue
		}
		rows = append(rows, Transaction{
			Chain:           "monad",
			Hash:            tx.Hash,
			From:            tx.From,
			To:              tx.To,
			Amount:          formatAmountFromBigInt(tx.Value, 18),
			Symbol:          getNativeSymbol("monad"),
			ContractAddress: "native",
			Direction:       "outgoing",
			Timestamp:       tx.Timestamp,
			Status:          tx.Status,
			ExplorerURL:     ExplorerTxURL("monad", tx.Hash),
		})
	}
	updateSlowChainState("monad", address, func(state *slowChainState) {
		state.LastNativeTxCount = latestCount
	})
	return rows, nil
}

func fetchMonadERC20History(endpoints []string, address string, limit int) ([]Transaction, error) {
	head, err := monadBlockNumber(endpoints)
	if err != nil {
		return nil, err
	}
	topicAddress, err := monadTopicAddress(address)
	if err != nil {
		return nil, err
	}
	lowerBound := slowChainLogLowerBound("monad", address, head, endpoints)

	timestampCache := make(map[string]time.Time)
	rows := make([]Transaction, 0, limit*2)
	for _, spec := range []struct {
		direction string
		topics    []interface{}
	}{
		{direction: "outgoing", topics: []interface{}{monadERC20TransferTopic, topicAddress}},
		{direction: "incoming", topics: []interface{}{monadERC20TransferTopic, nil, topicAddress}},
	} {
		logs, err := monadFetchLogs(endpoints, lowerBound, head, spec.topics, limit*3)
		if err != nil {
			return rows, err
		}
		for _, entry := range logs {
			item, _ := entry.(map[string]interface{})
			if item == nil {
				continue
			}
			topics := asSlice(item["topics"])
			if len(topics) < 3 {
				continue
			}
			blockHex := strings.TrimSpace(stringValue(item["blockNumber"]))
			ts, ok := timestampCache[blockHex]
			if !ok {
				ts, err = monadBlockTimestamp(endpoints, blockHex)
				if err != nil {
					return rows, err
				}
				timestampCache[blockHex] = ts
			}
			contract := strings.TrimSpace(stringValue(item["address"]))
			from := monadAddressFromTopic(stringValue(topics[1]))
			to := monadAddressFromTopic(stringValue(topics[2]))
			value := monadBigIntFromHex(stringValue(item["data"]))
			if value == nil || value.Sign() <= 0 {
				continue
			}

			symbol, decimals := fetchMonadERC20Meta(endpoints, contract)
			rows = append(rows, Transaction{
				Chain:           "monad",
				Hash:            strings.TrimSpace(stringValue(item["transactionHash"])),
				From:            from,
				To:              to,
				Amount:          formatAmountFromBigInt(value, decimals),
				Symbol:          symbol,
				ContractAddress: contract,
				Direction:       spec.direction,
				Timestamp:       ts,
				Status:          "success",
				ExplorerURL:     ExplorerTxURL("monad", stringValue(item["transactionHash"])),
			})
		}
	}
	updateSlowChainState("monad", address, func(state *slowChainState) {
		if head > state.HistoryScanBlock {
			state.HistoryScanBlock = head
		}
	})
	return rows, nil
}

func monadFetchLogs(endpoints []string, lowerBound, head int, topics []interface{}, want int) ([]interface{}, error) {
	logs := make([]interface{}, 0, want)
	chunkSize := monadLogsChunkSize
	for to := head; to >= lowerBound; {
		from := to - chunkSize + 1
		if from < lowerBound {
			from = lowerBound
		}
		res, err := rpcCallAny(endpoints, "eth_getLogs", []interface{}{
			map[string]interface{}{
				"fromBlock": fmt.Sprintf("0x%x", from),
				"toBlock":   fmt.Sprintf("0x%x", to),
				"topics":    topics,
			},
		})
		if err != nil {
			if chunkSize > monadLogsMinChunkSize {
				chunkSize /= 2
				if chunkSize < monadLogsMinChunkSize {
					chunkSize = monadLogsMinChunkSize
				}
				continue
			}
			return logs, err
		}
		logs = append(logs, asSlice(res["result"])...)
		if len(logs) >= want {
			return logs, nil
		}
		if from == 0 {
			break
		}
		to = from - 1
	}
	return logs, nil
}

func monadFindNativeTxForNonce(endpoints []string, address string, blockNumber, nonce int) (monadNativeTx, error) {
	fromBlock := maxInt(blockNumber-monadBlockNeighborhood, 0)
	toBlock := blockNumber + monadBlockNeighborhood
	blocks := fetchEVMBlocksBatchAny(endpoints, fromBlock, toBlock)
	for candidate := fromBlock; candidate <= toBlock; candidate++ {
		block := blocks[candidate]
		if block == nil {
			res, err := rpcCallAny(endpoints, "eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", candidate), true})
			if err != nil {
				continue
			}
			block, _ = res["result"].(map[string]interface{})
		}
		if block == nil {
			continue
		}
		timestamp := monadTimeFromHex(stringValue(block["timestamp"]))
		for _, entry := range asSlice(block["transactions"]) {
			tx, _ := entry.(map[string]interface{})
			if tx == nil {
				continue
			}
			if !strings.EqualFold(stringValue(tx["from"]), address) {
				continue
			}
			if monadIntFromHex(stringValue(tx["nonce"])) != nonce {
				continue
			}
			receiptRes, err := rpcCallAny(endpoints, "eth_getTransactionReceipt", []interface{}{stringValue(tx["hash"])})
			if err != nil {
				return monadNativeTx{}, err
			}
			receipt, _ := receiptRes["result"].(map[string]interface{})
			status := "success"
			if monadIntFromHex(stringValue(receipt["status"])) == 0 {
				status = "failed"
			}
			return monadNativeTx{
				Hash:      stringValue(tx["hash"]),
				From:      stringValue(tx["from"]),
				To:        stringValue(tx["to"]),
				Value:     monadBigIntFromHex(stringValue(tx["value"])),
				Timestamp: timestamp,
				Status:    status,
			}, nil
		}
	}
	return monadNativeTx{}, fmt.Errorf("monad tx not found for nonce=%d near block=%d", nonce, blockNumber)
}

func monadFindLowerBound(endpoints []string, address string, head, targetCount int) (int, error) {
	best := maxInt(head-slowChainLookbackBlocks, 0)
	for distance := monadNonceProbeStep; distance <= slowChainLookbackBlocks; distance += monadNonceProbeStep {
		candidate := head - distance
		if candidate < 0 {
			candidate = 0
		}
		count, err := monadTxCount(endpoints, address, fmt.Sprintf("0x%x", candidate))
		if err != nil {
			continue
		}
		best = candidate
		if count < targetCount {
			return candidate, nil
		}
		if candidate == 0 {
			break
		}
	}
	return best, nil
}

func monadFindFirstBlockWithCountAtLeast(endpoints []string, address string, low, high, targetCount int) (int, error) {
	lowCount, err := monadTxCount(endpoints, address, fmt.Sprintf("0x%x", low))
	if err == nil && lowCount >= targetCount {
		return low, nil
	}
	for low < high {
		mid := low + (high-low)/2
		count, err := monadTxCount(endpoints, address, fmt.Sprintf("0x%x", mid))
		if err != nil {
			return 0, err
		}
		if count >= targetCount {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low, nil
}

func monadBlockNumber(endpoints []string) (int, error) {
	res, err := rpcCallAny(endpoints, "eth_blockNumber", []interface{}{})
	if err != nil {
		return 0, err
	}
	return monadIntFromHex(stringValue(res["result"])), nil
}

func monadBlockTimestamp(endpoints []string, blockHex string) (time.Time, error) {
	res, err := rpcCallAny(endpoints, "eth_getBlockByNumber", []interface{}{blockHex, false})
	if err != nil {
		return time.Time{}, err
	}
	block, _ := res["result"].(map[string]interface{})
	if block == nil {
		return time.Time{}, fmt.Errorf("monad block %s not found", blockHex)
	}
	return monadTimeFromHex(stringValue(block["timestamp"])), nil
}

func monadTxCount(endpoints []string, address, blockRef string) (int, error) {
	res, err := rpcCallAny(endpoints, "eth_getTransactionCount", []interface{}{address, blockRef})
	if err != nil {
		return 0, err
	}
	return monadIntFromHex(stringValue(res["result"])), nil
}

func fetchMonadERC20Meta(endpoints []string, contract string) (string, int) {
	cacheKey := "monad:" + strings.ToLower(strings.TrimSpace(contract))
	mu.RLock()
	symbol, symbolOK := symCache[cacheKey]
	decimals, decimalsOK := decCache[cacheKey]
	mu.RUnlock()
	if symbolOK && decimalsOK {
		return symbol, decimals
	}

	decimals = 18
	if res, err := rpcCallAny(endpoints, "eth_call", []interface{}{
		map[string]interface{}{"to": contract, "data": "0x313ce567"},
		"latest",
	}); err == nil {
		if value := monadBigIntFromHex(stringValue(res["result"])); value != nil && value.Sign() >= 0 {
			decimals = int(value.Int64())
		}
	}

	symbol = "TOKEN"
	if res, err := rpcCallAny(endpoints, "eth_call", []interface{}{
		map[string]interface{}{"to": contract, "data": "0x95d89b41"},
		"latest",
	}); err == nil {
		if parsed := monadDecodeABIString(stringValue(res["result"])); parsed != "" {
			symbol = parsed
		}
	}

	mu.Lock()
	symCache[cacheKey] = symbol
	decCache[cacheKey] = decimals
	mu.Unlock()
	return symbol, decimals
}

func rpcCallAny(endpoints []string, method string, params interface{}) (map[string]interface{}, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		res, err := rpcCall(endpoint, method, params)
		if err == nil {
			if rpcErr, ok := res["error"].(map[string]interface{}); ok && rpcErr != nil {
				lastErr = fmt.Errorf("rpc %s returned %s", method, strings.TrimSpace(stringValue(rpcErr["message"])))
				continue
			}
			return res, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no RPC endpoints configured")
	}
	return nil, lastErr
}

func monadDecodeABIString(raw string) string {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return ""
	}
	data, err := hex.DecodeString(raw)
	if err != nil || len(data) == 0 {
		return ""
	}
	if len(data) == 32 {
		return strings.TrimRightFunc(string(data), func(r rune) bool { return r == 0 || !unicode.IsPrint(r) })
	}
	if len(data) >= 96 {
		offset := new(big.Int).SetBytes(data[:32]).Int64()
		if offset >= 0 && int(offset)+64 <= len(data) {
			length := new(big.Int).SetBytes(data[offset : offset+32]).Int64()
			start := int(offset) + 32
			end := start + int(length)
			if length > 0 && end <= len(data) {
				return strings.TrimRightFunc(string(data[start:end]), func(r rune) bool { return r == 0 || !unicode.IsPrint(r) })
			}
		}
	}
	return ""
}

func monadTopicAddress(address string) (string, error) {
	address = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(address)), "0x")
	if address == "" {
		return "", fmt.Errorf("missing monad topic address")
	}
	if len(address) > 64 {
		return "", fmt.Errorf("invalid monad topic address length: %d", len(address))
	}
	for _, ch := range address {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return "", fmt.Errorf("invalid monad topic address: %q", address)
		}
	}
	return "0x" + strings.Repeat("0", 64-len(address)) + address, nil
}

func monadAddressFromTopic(topic string) string {
	topic = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(topic)), "0x")
	if len(topic) < 40 {
		return ""
	}
	return "0x" + topic[len(topic)-40:]
}

func monadBigIntFromHex(raw string) *big.Int {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return big.NewInt(0)
	}
	out := new(big.Int)
	if _, ok := out.SetString(raw, 16); !ok {
		return nil
	}
	return out
}

func monadIntFromHex(raw string) int {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseInt(raw, 16, 64)
	if err != nil {
		return 0
	}
	return int(value)
}

func monadTimeFromHex(raw string) time.Time {
	value := monadIntFromHex(raw)
	if value <= 0 {
		return time.Now()
	}
	return time.Unix(int64(value), 0).UTC()
}

func monadScanTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().UTC()
	}
	unix, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Now().UTC()
	}
	return time.Unix(unix, 0).UTC()
}

func monadScanStatus(receiptStatus, isError string) string {
	if strings.TrimSpace(receiptStatus) == "1" && strings.TrimSpace(isError) == "0" {
		return "success"
	}
	if strings.TrimSpace(receiptStatus) == "0" || strings.TrimSpace(isError) == "1" {
		return "failed"
	}
	return "success"
}

func monadScanInternalStatus(isError, errCode string) string {
	if strings.TrimSpace(isError) == "1" || strings.TrimSpace(errCode) != "" {
		return "failed"
	}
	return "success"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
