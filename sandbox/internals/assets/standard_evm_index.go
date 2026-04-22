package assets

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

const standardEVMContractProbeLimit = 128
const (
	publicRPCNativeHistoryLimit  = 1000
	standardEVMNativeHistoryTime = 60 * time.Second
	recentWindowBlockScanCutover = 25
	blockBatchScanSize           = 40
)

func fetchStandardEVMAssets(chain string, endpoints []string, address string) ([]Asset, error) {
	results := make([]Asset, 0, 4)

	if !suppressNativeBalanceDisplay(chain) {
		res, err := rpcCallAny(endpoints, "eth_getBalance", []interface{}{address, "latest"})
		if err != nil {
			return nil, err
		}
		if raw := stringValue(res["result"]); raw != "" {
			if value := monadBigIntFromHex(raw); value != nil {
				fValue, _ := new(big.Float).SetInt(value).Float64()
				results = append(results, Asset{
					Chain:           chain,
					ContractAddress: "native",
					Symbol:          getNativeSymbol(chain),
					BalanceStr:      value.String(),
					Decimals:        18,
					UIBalance:       fValue / 1e18,
					ExplorerURL:     ExplorerAddressURL(chain, address),
				})
			}
		}
	}

	contracts, err := discoverStandardERC20Contracts(chain, endpoints, address, standardEVMContractProbeLimit)
	if err != nil {
		return results, nil
	}
	for _, contract := range contracts {
		balance, err := fetchStandardERC20Balance(endpoints, contract, address)
		if err != nil || balance == nil || balance.Sign() <= 0 {
			continue
		}

		symbol, decimals := fetchStandardERC20Meta(chain, endpoints, contract)
		fValue, _ := new(big.Float).SetInt(balance).Float64()
		divisor := 1.0
		for i := 0; i < decimals; i++ {
			divisor *= 10
		}
		results = append(results, Asset{
			Chain:           chain,
			ContractAddress: contract,
			Symbol:          symbol,
			BalanceStr:      balance.String(),
			Decimals:        decimals,
			UIBalance:       fValue / divisor,
			ExplorerURL:     ExplorerTokenURL(chain, contract),
		})
	}

	return results, nil
}

func fetchStandardEVMHistory(chain string, endpoints []string, address string, limit int) ([]Transaction, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil, fmt.Errorf("missing %s address", chain)
	}
	if limit <= 0 {
		limit = 50
	}

	nativeRows, nativeErr := fetchStandardEVMNativeHistory(chain, endpoints, address, limit)
	tokenRows, tokenErr := fetchStandardEVMERC20History(chain, endpoints, address, limit)

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
		case nativeErr != nil && tokenErr != nil:
			return nil, fmt.Errorf("%s native history: %v; %s erc20 history: %v", chain, nativeErr, chain, tokenErr)
		case nativeErr != nil:
			return nil, nativeErr
		case tokenErr != nil:
			return nil, tokenErr
		}
	}
	return merged, nil
}

func fetchStandardEVMNativeHistory(chain string, endpoints []string, address string, limit int) ([]Transaction, error) {
	if usesLightweightPublicEVMHistory(chain, endpoints) && limit > publicRPCNativeHistoryLimit {
		limit = publicRPCNativeHistoryLimit
	}
	head, err := monadBlockNumber(endpoints)
	if err != nil {
		return nil, err
	}
	latestCount, err := monadTxCount(endpoints, address, "latest")
	if err != nil {
		return nil, err
	}
	var state slowChainState
	hasPersistentState := usesPersistentCursorChain(chain)
	if hasPersistentState {
		state = getSlowChainState(chain, address)
	}
	lowerBound := slowChainLogLowerBound(chain, address, head, endpoints)
	if latestCount == 0 {
		if hasPersistentState {
			updateSlowChainState(chain, address, func(state *slowChainState) {
				state.LastNativeTxCount = 0
			})
		}
		incomingRows, _ := fetchStandardEVMNativeIncomingHistoryByBlockScan(chain, endpoints, address, head, lowerBound, limit, time.Now().Add(standardEVMNativeHistoryTime))
		if len(incomingRows) == 0 {
			return nil, nil
		}
		return incomingRows, nil
	}

	lowerCount := 0
	if lowerResp, lowerErr := rpcCallAny(endpoints, "eth_getTransactionCount", []interface{}{address, fmt.Sprintf("0x%x", lowerBound)}); lowerErr == nil {
		lowerCount = monadIntFromHex(stringValue(lowerResp["result"]))
		if lowerCount > latestCount {
			lowerCount = latestCount
		}
	} else if hasPersistentState && state.LastNativeTxCount > 0 && lowerBound > 0 {
		lowerCount = state.LastNativeTxCount
		if lowerCount > latestCount {
			lowerCount = latestCount
		}
	}

	minCount := latestCount - limit + 1
	if minCount < 1 {
		minCount = 1
	}
	if lowerCount > 0 {
		windowMin := lowerCount + 1
		if windowMin > minCount {
			minCount = windowMin
		}
	}
	if hasPersistentState {
		if state.LastNativeTxCount >= latestCount {
			return nil, nil
		}
		if state.LastNativeTxCount > 0 {
			incrementalMin := state.LastNativeTxCount + 1
			if incrementalMin > minCount {
				minCount = incrementalMin
			}
		}
	}
	if probed, err := monadFindLowerBound(endpoints, address, head, minCount); err == nil && probed >= 0 {
		lowerBound = probed
	}

	outgoingRows := make([]Transaction, 0, latestCount-minCount+1)
	recentDelta := latestCount - lowerCount
	if recentDelta >= recentWindowBlockScanCutover {
		want := limit
		if recentDelta < want {
			want = recentDelta
		}
		if want > 0 {
			if rows, ok := fetchStandardEVMNativeHistoryByBlockScan(chain, endpoints, address, head, lowerBound, want, time.Now().Add(standardEVMNativeHistoryTime)); ok {
				outgoingRows = rows
				if hasPersistentState {
					updateSlowChainState(chain, address, func(state *slowChainState) {
						state.LastNativeTxCount = latestCount
					})
				}
				incomingRows, _ := fetchStandardEVMNativeIncomingHistoryByBlockScan(chain, endpoints, address, head, lowerBound, limit, time.Now().Add(standardEVMNativeHistoryTime))
				return mergeHistory(outgoingRows, incomingRows, limit), nil
			}
		}
	}

	high := head
	deadline := time.Now().Add(standardEVMNativeHistoryTime)
	for targetCount := latestCount; targetCount >= minCount; targetCount-- {
		if time.Now().After(deadline) {
			break
		}
		blockNumber, err := monadFindFirstBlockWithCountAtLeast(endpoints, address, lowerBound, high, targetCount)
		if err != nil {
			return outgoingRows, err
		}
		tx, err := monadFindNativeTxForNonce(endpoints, address, blockNumber, targetCount-1)
		if err != nil {
			high = blockNumber
			continue
		}
		high = blockNumber
		amount := "0"
		if tx.Value != nil {
			amount = formatAmountFromBigInt(tx.Value, 18)
		}
		outgoingRows = append(outgoingRows, Transaction{
			Chain:           chain,
			Hash:            tx.Hash,
			From:            tx.From,
			To:              tx.To,
			Amount:          amount,
			Symbol:          getNativeSymbol(chain),
			ContractAddress: "native",
			Direction:       "outgoing",
			Timestamp:       tx.Timestamp,
			Status:          tx.Status,
			ExplorerURL:     ExplorerTxURL(chain, tx.Hash),
		})
	}
	if hasPersistentState {
		updateSlowChainState(chain, address, func(state *slowChainState) {
			state.LastNativeTxCount = latestCount
		})
	}
	incomingRows, _ := fetchStandardEVMNativeIncomingHistoryByBlockScan(chain, endpoints, address, head, lowerBound, limit, deadline)
	return mergeHistory(outgoingRows, incomingRows, limit), nil
}

func fetchStandardEVMNativeHistoryByBlockScan(chain string, endpoints []string, address string, head, lowerBound, limit int, deadline time.Time) ([]Transaction, bool) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" || limit <= 0 {
		return nil, false
	}

	rows := make([]Transaction, 0, limit)
	for batchTop := head; batchTop >= lowerBound; {
		if time.Now().After(deadline) {
			break
		}
		batchBottom := batchTop - blockBatchScanSize + 1
		if batchBottom < lowerBound {
			batchBottom = lowerBound
		}
		blocks := fetchEVMBlocksBatchAny(endpoints, batchBottom, batchTop)
		for blockNumber := batchTop; blockNumber >= batchBottom; blockNumber-- {
			if time.Now().After(deadline) {
				break
			}
			block := blocks[blockNumber]
			if block == nil {
				res, err := rpcCallAny(endpoints, "eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", blockNumber), true})
				if err != nil {
					continue
				}
				block, _ = res["result"].(map[string]interface{})
			}
			if block == nil {
				continue
			}
			timestamp := monadTimeFromHex(stringValue(block["timestamp"]))
			transactions := asSlice(block["transactions"])
			for i := len(transactions) - 1; i >= 0; i-- {
				tx, _ := transactions[i].(map[string]interface{})
				if tx == nil {
					continue
				}
				if !strings.EqualFold(stringValue(tx["from"]), address) {
					continue
				}
				status := "success"
				receiptRes, err := rpcCallAny(endpoints, "eth_getTransactionReceipt", []interface{}{stringValue(tx["hash"])})
				if err == nil {
					if receipt, _ := receiptRes["result"].(map[string]interface{}); receipt != nil && monadIntFromHex(stringValue(receipt["status"])) == 0 {
						status = "failed"
					}
				}
				value := monadBigIntFromHex(stringValue(tx["value"]))
				amount := "0"
				if value != nil {
					amount = formatAmountFromBigInt(value, 18)
				}
				rows = append(rows, Transaction{
					Chain:           chain,
					Hash:            stringValue(tx["hash"]),
					From:            stringValue(tx["from"]),
					To:              stringValue(tx["to"]),
					Amount:          amount,
					Symbol:          getNativeSymbol(chain),
					ContractAddress: "native",
					Direction:       "outgoing",
					Timestamp:       timestamp,
					Status:          status,
					ExplorerURL:     ExplorerTxURL(chain, stringValue(tx["hash"])),
				})
				if len(rows) >= limit {
					return rows, true
				}
			}
		}
		if batchBottom == 0 {
			break
		}
		batchTop = batchBottom - 1
	}
	return rows, len(rows) > 0
}

func fetchStandardEVMNativeIncomingHistoryByBlockScan(chain string, endpoints []string, address string, head, lowerBound, limit int, deadline time.Time) ([]Transaction, bool) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" || limit <= 0 {
		return nil, false
	}

	rows := make([]Transaction, 0, limit)
	for batchTop := head; batchTop >= lowerBound; {
		if time.Now().After(deadline) {
			break
		}
		batchBottom := batchTop - blockBatchScanSize + 1
		if batchBottom < lowerBound {
			batchBottom = lowerBound
		}
		blocks := fetchEVMBlocksBatchAny(endpoints, batchBottom, batchTop)
		for blockNumber := batchTop; blockNumber >= batchBottom; blockNumber-- {
			if time.Now().After(deadline) {
				break
			}
			block := blocks[blockNumber]
			if block == nil {
				res, err := rpcCallAny(endpoints, "eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", blockNumber), true})
				if err != nil {
					continue
				}
				block, _ = res["result"].(map[string]interface{})
			}
			if block == nil {
				continue
			}
			timestamp := monadTimeFromHex(stringValue(block["timestamp"]))
			transactions := asSlice(block["transactions"])
			for i := len(transactions) - 1; i >= 0; i-- {
				tx, _ := transactions[i].(map[string]interface{})
				if tx == nil {
					continue
				}
				from := stringValue(tx["from"])
				to := stringValue(tx["to"])
				if !strings.EqualFold(to, address) || strings.EqualFold(from, address) {
					continue
				}
				status := "success"
				receiptRes, err := rpcCallAny(endpoints, "eth_getTransactionReceipt", []interface{}{stringValue(tx["hash"])})
				if err == nil {
					if receipt, _ := receiptRes["result"].(map[string]interface{}); receipt != nil && monadIntFromHex(stringValue(receipt["status"])) == 0 {
						status = "failed"
					}
				}
				value := monadBigIntFromHex(stringValue(tx["value"]))
				amount := "0"
				if value != nil {
					amount = formatAmountFromBigInt(value, 18)
				}
				rows = append(rows, Transaction{
					Chain:           chain,
					Hash:            stringValue(tx["hash"]),
					From:            from,
					To:              to,
					Amount:          amount,
					Symbol:          getNativeSymbol(chain),
					ContractAddress: "native",
					Direction:       "incoming",
					Timestamp:       timestamp,
					Status:          status,
					ExplorerURL:     ExplorerTxURL(chain, stringValue(tx["hash"])),
				})
				if len(rows) >= limit {
					return rows, true
				}
			}
		}
		if batchBottom == 0 {
			break
		}
		batchTop = batchBottom - 1
	}
	return rows, len(rows) > 0
}

func usesLightweightPublicEVMHistory(chain string, endpoints []string) bool {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if chain == "ethereum" {
		return false
	}
	return !endpointSupportsAlchemyRPC(firstPublicRPCEndpoint(endpoints))
}

func fetchStandardEVMERC20History(chain string, endpoints []string, address string, limit int) ([]Transaction, error) {
	head, err := monadBlockNumber(endpoints)
	if err != nil {
		return nil, err
	}
	topicAddress, err := monadTopicAddress(address)
	if err != nil {
		return nil, err
	}
	lowerBound := slowChainLogLowerBound(chain, address, head, endpoints)

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

			symbol, decimals := fetchStandardERC20Meta(chain, endpoints, contract)
			rows = append(rows, Transaction{
				Chain:           chain,
				Hash:            strings.TrimSpace(stringValue(item["transactionHash"])),
				From:            from,
				To:              to,
				Amount:          formatAmountFromBigInt(value, decimals),
				Symbol:          symbol,
				ContractAddress: contract,
				Direction:       spec.direction,
				Timestamp:       ts,
				Status:          "success",
				ExplorerURL:     ExplorerTxURL(chain, stringValue(item["transactionHash"])),
			})
		}
	}
	if usesPersistentCursorChain(chain) {
		updateSlowChainState(chain, address, func(state *slowChainState) {
			if head > state.HistoryScanBlock {
				state.HistoryScanBlock = head
			}
		})
	}
	return rows, nil
}

func discoverStandardERC20Contracts(chain string, endpoints []string, address string, want int) ([]string, error) {
	head, err := monadBlockNumber(endpoints)
	if err != nil {
		return nil, err
	}
	topicAddress, err := monadTopicAddress(address)
	if err != nil {
		return nil, err
	}
	lowerBound := slowChainContractLowerBound(chain, address, head, endpoints)

	contracts := make([]string, 0, want)
	seen := make(map[string]struct{}, want)
	if usesPersistentCursorChain(chain) {
		state := getSlowChainState(chain, address)
		for _, contract := range state.KnownContracts {
			contract = strings.ToLower(strings.TrimSpace(contract))
			if contract == "" {
				continue
			}
			if _, ok := seen[contract]; ok {
				continue
			}
			seen[contract] = struct{}{}
			contracts = append(contracts, contract)
		}
	}
	var lastErr error
	for _, topics := range [][]interface{}{
		{monadERC20TransferTopic, topicAddress},
		{monadERC20TransferTopic, nil, topicAddress},
	} {
		logs, err := monadFetchLogs(endpoints, lowerBound, head, topics, want*3)
		if err != nil {
			lastErr = err
			continue
		}
		for _, entry := range logs {
			item, _ := entry.(map[string]interface{})
			if item == nil {
				continue
			}
			contract := strings.ToLower(strings.TrimSpace(stringValue(item["address"])))
			if contract == "" {
				continue
			}
			if _, ok := seen[contract]; ok {
				continue
			}
			seen[contract] = struct{}{}
			contracts = append(contracts, contract)
			if !usesPersistentCursorChain(chain) && len(contracts) >= want {
				return contracts, nil
			}
		}
	}
	if usesPersistentCursorChain(chain) {
		if len(contracts) > standardEVMContractProbeLimit {
			contracts = contracts[:standardEVMContractProbeLimit]
		}
		snapshot := append([]string(nil), contracts...)
		updateSlowChainState(chain, address, func(state *slowChainState) {
			state.KnownContracts = snapshot
			if head > state.ContractScanBlock {
				state.ContractScanBlock = head
			}
		})
	}
	if len(contracts) == 0 && lastErr != nil {
		return nil, lastErr
	}
	if len(contracts) > want {
		contracts = contracts[:want]
	}
	return contracts, nil
}

func fetchStandardERC20Balance(endpoints []string, contract, address string) (*big.Int, error) {
	address = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(address)), "0x")
	if address == "" {
		return big.NewInt(0), nil
	}
	res, err := rpcCallAny(endpoints, "eth_call", []interface{}{
		map[string]interface{}{"to": contract, "data": "0x70a08231" + strings.Repeat("0", 64-len(address)) + address},
		"latest",
	})
	if err != nil {
		return nil, err
	}
	value := monadBigIntFromHex(stringValue(res["result"]))
	if value == nil {
		return big.NewInt(0), nil
	}
	return value, nil
}

func fetchStandardERC20Meta(chain string, endpoints []string, contract string) (string, int) {
	cacheKey := strings.ToLower(strings.TrimSpace(chain + ":" + contract))
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
