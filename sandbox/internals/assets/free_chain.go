package assets

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"sandbox/pkg/bitcoinesplora"
)

const (
	bitcoinHistoryPages       = 5
	bitcoinRequestTimeout     = 1500 * time.Millisecond
	bitcoinTotalRefreshBudget = 30 * time.Second
	blockscoutHistoryPages    = 10
)

func FetchFreeChainData(chain, address string) ([]Asset, []Transaction, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if chain == "" || address == "" {
		return nil, nil, fmt.Errorf("missing chain or address")
	}

	switch chain {
	case "ethereum":
		return fetchFastEVMChainData(chain, address, func() ([]Asset, []Transaction, error) {
			return fetchBlockscoutChain(chain, "https://eth.blockscout.com/api/v2", address)
		})
	case "base":
		return fetchFastEVMChainData(chain, address, func() ([]Asset, []Transaction, error) {
			return fetchBlockscoutChain(chain, "https://base.blockscout.com/api/v2", address)
		})
	case "arbitrum":
		return fetchFastEVMChainData(chain, address, func() ([]Asset, []Transaction, error) {
			return fetchBlockscoutChain(chain, "https://arbitrum.blockscout.com/api/v2", address)
		})
	case "bsc":
		return fetchFastEVMChainData(chain, address, func() ([]Asset, []Transaction, error) {
			return fetchEthplorerChain(chain, "https://api.binplorer.com", address)
		})
	case "tempo":
		return fetchTempoFastChainData(address, 100)
	case "monad":
		return fetchMonadFastChainData(address, 100)
	case "solana":
		endpoints := publicAssetRPCURLs(chain)
		return fetchSolana(endpoints, address), fetchSolanaHistory(address, endpoints), nil
	case "sui":
		url := "https://fullnode.mainnet.sui.io"
		return fetchSui(url, address), fetchSuiHistory(address, url), nil
	case "bitcoin":
		return fetchBitcoin(address)
	default:
		return nil, nil, fmt.Errorf("free rpc not supported for %s", chain)
	}
}

func fetchFastEVMChainData(chain, address string, fallback func() ([]Asset, []Transaction, error)) ([]Asset, []Transaction, error) {
	if endpoint := alchemyRPCURL(chain); endpoint != "" {
		assets, assetErr := fetchEVM(chain, endpoint, address)
		if assetErr == nil {
			history, histErr := fetchEVMHistory(chain, endpoint, address)
			if histErr == nil {
				return assets, history, nil
			}
			if len(assets) > 0 {
				return assets, []Transaction{}, nil
			}
		}
	}
	if fallback != nil {
		return fallback()
	}
	return nil, nil, fmt.Errorf("%s fast refresh unsupported", chain)
}

func fetchTempoFastChainData(address string, limit int) ([]Asset, []Transaction, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil, nil, fmt.Errorf("missing tempo address")
	}
	_ = limit

	endpoints := tempoFastRPCURLs()
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("tempo fast refresh: no rpc endpoints configured")
	}

	state := getSlowChainState("tempo", address)
	seenContracts := make(map[string]struct{}, len(state.KnownContracts))
	assets := make([]Asset, 0, len(state.KnownContracts))
	for _, contract := range state.KnownContracts {
		contract = strings.ToLower(strings.TrimSpace(contract))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seenContracts[contract]; ok {
			continue
		}
		seenContracts[contract] = struct{}{}

		balance, err := fetchStandardERC20Balance(endpoints, contract, address)
		if err != nil || balance == nil || balance.Sign() <= 0 {
			continue
		}
		symbol, decimals := fetchStandardERC20Meta("tempo", endpoints, contract)
		fValue, _ := new(big.Float).SetInt(balance).Float64()
		divisor := 1.0
		for i := 0; i < decimals; i++ {
			divisor *= 10
		}
		assets = append(assets, Asset{
			Chain:           "tempo",
			ContractAddress: contract,
			Symbol:          symbol,
			BalanceStr:      balance.String(),
			Decimals:        decimals,
			UIBalance:       fValue / divisor,
			ExplorerURL:     ExplorerTokenURL("tempo", contract),
		})
	}
	return assets, nil, nil
}

func tempoFastRPCURLs() []string {
	seen := make(map[string]struct{})
	urls := make([]string, 0, 4)
	add := func(url string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}

	if override := strings.TrimSpace(os.Getenv("CLAY_RPC_TEMPO")); override != "" {
		for _, item := range strings.Split(override, ",") {
			add(item)
		}
	}
	add(alchemyRPCURL("tempo"))
	for _, endpoint := range publicAssetRPCURLs("tempo") {
		add(endpoint)
	}
	return urls
}

type bitcoinAddressStats struct {
	FundedTXOSum int64 `json:"funded_txo_sum"`
	SpentTXOSum  int64 `json:"spent_txo_sum"`
}

type bitcoinAddressResponse struct {
	ChainStats   bitcoinAddressStats `json:"chain_stats"`
	MempoolStats bitcoinAddressStats `json:"mempool_stats"`
}

type bitcoinTxStatus struct {
	Confirmed bool  `json:"confirmed"`
	BlockTime int64 `json:"block_time"`
}

type bitcoinTxPrevout struct {
	ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	Value               int64  `json:"value"`
}

type bitcoinTxVin struct {
	Prevout *bitcoinTxPrevout `json:"prevout"`
}

type bitcoinTxVout struct {
	ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	Value               int64  `json:"value"`
}

type bitcoinTxResponse struct {
	TxID   string          `json:"txid"`
	Status bitcoinTxStatus `json:"status"`
	Vin    []bitcoinTxVin  `json:"vin"`
	Vout   []bitcoinTxVout `json:"vout"`
}

func fetchBitcoin(address string) ([]Asset, []Transaction, error) {
	address = strings.TrimSpace(address)
	deadline := time.Now().Add(bitcoinTotalRefreshBudget)
	info, baseURL, err := fetchBitcoinAddressInfo(address, deadline)
	if err != nil {
		return nil, nil, err
	}

	total := (info.ChainStats.FundedTXOSum - info.ChainStats.SpentTXOSum) + (info.MempoolStats.FundedTXOSum - info.MempoolStats.SpentTXOSum)
	if total < 0 {
		total = 0
	}

	assets := []Asset{{
		Chain:           "bitcoin",
		ContractAddress: "native",
		Symbol:          getNativeSymbol("bitcoin"),
		BalanceStr:      strconv.FormatInt(total, 10),
		Decimals:        8,
		UIBalance:       float64(total) / 1e8,
		ExplorerURL:     ExplorerAddressURL("bitcoin", address),
	}}

	history, _ := fetchBitcoinHistoryAcrossBases(address, baseURL, deadline)
	return assets, history, nil
}

func fetchTron(address string) ([]Asset, []Transaction, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, nil, fmt.Errorf("missing tron address")
	}

	info, err := getJSONMap(tronScanURL("/accountv2", url.Values{
		"address": []string{address},
	}))
	if err != nil {
		return nil, nil, err
	}

	nativeRaw := strings.TrimSpace(firstNonEmptyString(
		stringValue(info["balance"]),
		stringValue(info["balanceInSun"]),
		stringValue(info["balance_in_sun"]),
		stringValue(info["trxBalance"]),
		stringValue(info["balance_str"]),
	))
	if nativeRaw == "" {
		nativeRaw = "0"
	}

	assets := []Asset{{
		Chain:           "tron",
		ContractAddress: "native",
		Symbol:          "TRX",
		BalanceStr:      nativeRaw,
		Decimals:        6,
		UIBalance:       decimalToFloat(nativeRaw, 6),
		ExplorerURL:     ExplorerAddressURL("tron", address),
	}}
	assets = append(assets, fetchTronTokenAssets(info)...)

	return assets, fetchTronHistory(address), nil
}

func fetchTronHistory(address string) []Transaction {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}

	seen := make(map[string]struct{})
	rows := make([]Transaction, 0, 64)
	for _, filterKey := range []string{"fromAddress", "toAddress"} {
		info, err := getJSONMap(tronScanURL("/transaction", url.Values{
			filterKey: []string{address},
			"start":   []string{"0"},
			"limit":   []string{"50"},
			"sort":    []string{"-timestamp"},
			"reverse": []string{"true"},
			"count":   []string{"true"},
		}))
		if err != nil {
			continue
		}
		for _, item := range asSlice(info["data"]) {
			row, _ := item.(map[string]interface{})
			if row == nil {
				continue
			}
			tx := tronTransactionFromRow(address, row)
			if strings.TrimSpace(tx.Hash) == "" {
				continue
			}
			key := strings.Join([]string{
				strings.ToLower(strings.TrimSpace(tx.Hash)),
				strings.ToLower(strings.TrimSpace(tx.From)),
				strings.ToLower(strings.TrimSpace(tx.To)),
				strings.ToLower(strings.TrimSpace(tx.ContractAddress)),
				strings.TrimSpace(tx.Amount),
				strings.ToLower(strings.TrimSpace(tx.Symbol)),
				strings.ToLower(strings.TrimSpace(tx.Direction)),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rows = append(rows, tx)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Timestamp.Equal(rows[j].Timestamp) {
			return rows[i].Hash > rows[j].Hash
		}
		return rows[i].Timestamp.After(rows[j].Timestamp)
	})
	if len(rows) > persistedHistoryLimit {
		rows = rows[:persistedHistoryLimit]
	}
	return rows
}

func tronScanURL(path string, query url.Values) string {
	base := strings.TrimRight("https://apilist.tronscanapi.com/api", "/")
	path = "/" + strings.TrimLeft(strings.TrimSpace(path), "/")
	if query == nil || len(query) == 0 {
		return base + path
	}
	return base + path + "?" + query.Encode()
}

func fetchTronTokenAssets(info map[string]interface{}) []Asset {
	if info == nil {
		return nil
	}
	candidates := []interface{}{
		info["tokens"],
		info["tokenBalances"],
		info["trc20token_balances"],
		info["trc20Tokens"],
		info["data"],
	}

	assets := make([]Asset, 0, 16)
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		for _, item := range asSlice(candidate) {
			row, _ := item.(map[string]interface{})
			if row == nil {
				continue
			}
			tokenInfo, _ := row["tokenInfo"].(map[string]interface{})
			if tokenInfo == nil {
				tokenInfo, _ = row["token"].(map[string]interface{})
			}

			contract := firstNonEmptyString(
				stringValue(row["tokenId"]),
				stringValue(row["contractAddress"]),
				stringValue(row["token_address"]),
				stringValue(row["address"]),
				stringValue(row["contract_address"]),
				stringValue(tokenInfo["tokenId"]),
				stringValue(tokenInfo["address"]),
				stringValue(tokenInfo["contractAddress"]),
			)
			if contract == "" || contract == "native" || contract == "_" {
				continue
			}
			if _, ok := seen[strings.ToLower(contract)]; ok {
				continue
			}

			symbol := firstNonEmptyString(
				stringValue(row["tokenAbbr"]),
				stringValue(row["symbol"]),
				stringValue(row["tokenSymbol"]),
				stringValue(tokenInfo["tokenAbbr"]),
				stringValue(tokenInfo["symbol"]),
				stringValue(tokenInfo["tokenName"]),
			)
			if symbol == "" {
				symbol = "TOKEN"
			}

			decimals := atoiDefault(firstNonEmptyString(
				stringValue(row["tokenDecimal"]),
				stringValue(row["decimals"]),
				stringValue(tokenInfo["tokenDecimal"]),
				stringValue(tokenInfo["decimals"]),
			), 6)
			rawBalance := firstNonEmptyString(
				stringValue(row["balance"]),
				stringValue(row["quantity"]),
				stringValue(row["amount"]),
				stringValue(row["tokenBalance"]),
				stringValue(tokenInfo["balance"]),
			)
			if rawBalance == "" {
				continue
			}

			cacheTokenMeta("tron", contract, symbol, decimals)
			seen[strings.ToLower(contract)] = struct{}{}
			assets = append(assets, Asset{
				Chain:           "tron",
				ContractAddress: contract,
				Symbol:          symbol,
				BalanceStr:      rawBalance,
				Decimals:        decimals,
				UIBalance:       decimalToFloat(rawBalance, decimals),
				ExplorerURL:     ExplorerTokenURL("tron", contract),
			})
		}
	}
	return assets
}

func tronTransactionFromRow(address string, row map[string]interface{}) Transaction {
	hash := strings.TrimSpace(firstNonEmptyString(
		stringValue(row["hash"]),
		stringValue(row["txID"]),
		stringValue(row["txid"]),
		stringValue(row["transactionHash"]),
	))
	from := strings.TrimSpace(firstNonEmptyString(
		stringValue(row["fromAddress"]),
		stringValue(row["ownerAddress"]),
		stringValue(row["owner_address"]),
		stringValue(row["from"]),
	))
	to := strings.TrimSpace(firstNonEmptyString(
		stringValue(row["toAddress"]),
		stringValue(row["to_address"]),
		stringValue(row["to"]),
	))
	contractData, _ := row["contractData"].(map[string]interface{})
	tokenInfo, _ := row["tokenInfo"].(map[string]interface{})
	if tokenInfo == nil && contractData != nil {
		tokenInfo, _ = contractData["tokenInfo"].(map[string]interface{})
	}

	symbol := "TRX"
	contract := "native"
	decimals := 6
	amountRaw := firstNonEmptyString(
		stringValue(row["amount"]),
		stringValue(row["value"]),
	)
	if contractData != nil {
		if amountRaw == "" {
			amountRaw = firstNonEmptyString(
				stringValue(contractData["amount"]),
				stringValue(contractData["value"]),
				stringValue(contractData["quantity"]),
			)
		}
	}
	if tokenInfo != nil {
		symbol = firstNonEmptyString(
			stringValue(tokenInfo["tokenAbbr"]),
			stringValue(tokenInfo["symbol"]),
			stringValue(tokenInfo["tokenName"]),
		)
		if symbol == "" {
			symbol = "TOKEN"
		}
		contract = firstNonEmptyString(
			stringValue(tokenInfo["tokenId"]),
			stringValue(tokenInfo["address"]),
			stringValue(tokenInfo["contractAddress"]),
			stringValue(row["tokenId"]),
			stringValue(row["contractAddress"]),
		)
		if contract == "" {
			contract = "native"
		}
		decimals = atoiDefault(firstNonEmptyString(
			stringValue(tokenInfo["tokenDecimal"]),
			stringValue(tokenInfo["decimals"]),
		), 6)
		if amountRaw == "" {
			amountRaw = firstNonEmptyString(
				stringValue(tokenInfo["amount"]),
				stringValue(tokenInfo["quantity"]),
				stringValue(tokenInfo["value"]),
			)
		}
	}
	if amountRaw == "" {
		amountRaw = "0"
	}

	direction := direction(from, to, address)
	if direction == "" {
		if strings.EqualFold(from, address) {
			direction = "outgoing"
		} else if strings.EqualFold(to, address) {
			direction = "incoming"
		} else {
			direction = "incoming"
		}
	}

	status := "success"
	if revert, _ := row["revert"].(bool); revert {
		status = "failed"
	} else if confirmed, _ := row["confirmed"].(bool); !confirmed {
		status = "pending"
	}

	cacheTokenMeta("tron", contract, symbol, decimals)
	return Transaction{
		Chain:           "tron",
		Hash:            hash,
		From:            from,
		To:              to,
		Amount:          formatAmountFromString(amountRaw, decimals),
		Symbol:          symbol,
		ContractAddress: contract,
		Direction:       direction,
		Timestamp:       parseAnyTime(firstNonEmptyValue(row["timestamp"], row["blockTime"], row["createTime"])),
		Status:          status,
		ExplorerURL:     ExplorerTxURL("tron", hash),
	}
}

func firstNonEmptyValue(values ...interface{}) interface{} {
	for _, value := range values {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		default:
			if strings.TrimSpace(stringValue(v)) != "" {
				return v
			}
		}
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if s := strings.TrimSpace(value); s != "" {
			return s
		}
	}
	return ""
}

func fetchBitcoinAddressInfo(address string, deadline time.Time) (bitcoinAddressResponse, string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return bitcoinAddressResponse{}, "", fmt.Errorf("missing bitcoin address")
	}

	path := "/address/" + url.PathEscape(address)
	var lastErr error
	for _, b := range bitcoinesplora.Bases() {
		base := strings.TrimRight(strings.TrimSpace(b), "/")
		if base == "" {
			continue
		}
		info := bitcoinAddressResponse{}
		err := getJSONWithClient(bitcoinClient(deadline), base+path, &info)
		if err == nil {
			return info, base, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			break
		}
	}
	if lastErr == nil {
		return bitcoinAddressResponse{}, "", fmt.Errorf("bitcoin esplora: no API bases configured")
	}
	return bitcoinAddressResponse{}, "", lastErr
}

func fetchBitcoinHistoryAcrossBases(address, preferredBase string, deadline time.Time) ([]Transaction, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, fmt.Errorf("missing bitcoin address")
	}

	var lastErr error
	tried := make(map[string]struct{})
	tryBase := func(base string) ([]Transaction, bool) {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			return nil, false
		}
		if _, ok := tried[base]; ok {
			return nil, false
		}
		tried[base] = struct{}{}
		rows, err := fetchBitcoinHistoryFromBase(base, address, deadline)
		if err == nil {
			return rows, true
		}
		lastErr = err
		return nil, false
	}

	if rows, ok := tryBase(preferredBase); ok {
		return rows, nil
	}

	for _, b := range bitcoinesplora.Bases() {
		if time.Now().After(deadline) {
			break
		}
		if rows, ok := tryBase(b); ok {
			return rows, nil
		}
	}

	if lastErr == nil {
		return nil, fmt.Errorf("bitcoin history: no API bases configured")
	}
	return nil, lastErr
}

func fetchBitcoinHistoryFromBase(baseURL, address string, deadline time.Time) ([]Transaction, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	address = strings.TrimSpace(address)
	if baseURL == "" || address == "" {
		return nil, fmt.Errorf("missing bitcoin base url or address")
	}

	rows := make([]Transaction, 0, 32)
	seenTxID := ""

	for page := 0; page < bitcoinHistoryPages; page++ {
		url := baseURL + "/address/" + address + "/txs"
		if seenTxID != "" {
			url = baseURL + "/address/" + address + "/txs/chain/" + seenTxID
		}

		var txs []bitcoinTxResponse
		if err := getJSONWithClient(bitcoinClient(deadline), url, &txs); err != nil {
			if page == 0 {
				return nil, err
			}
			break
		}
		if len(txs) == 0 {
			break
		}

		seenTxID = txs[len(txs)-1].TxID
		for _, tx := range txs {
			if row, keep := bitcoinTxToHistoryRow(address, tx); keep {
				rows = append(rows, row)
			}
		}
	}

	var mempoolTxs []bitcoinTxResponse
	if err := getJSONWithClient(bitcoinClient(deadline), baseURL+"/address/"+address+"/txs/mempool", &mempoolTxs); err == nil {
		for _, tx := range mempoolTxs {
			if row, keep := bitcoinTxToHistoryRow(address, tx); keep {
				rows = append(rows, row)
			}
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].Timestamp.After(rows[j].Timestamp)
	})
	if len(rows) > 50 {
		rows = rows[:50]
	}
	return rows, nil
}

func bitcoinClient(deadline time.Time) *http.Client {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	if timeout > bitcoinRequestTimeout {
		timeout = bitcoinRequestTimeout
	}
	return &http.Client{Timeout: timeout}
}

func bitcoinTxToHistoryRow(address string, tx bitcoinTxResponse) (Transaction, bool) {
	txTime := time.Unix(tx.Status.BlockTime, 0).UTC()
	if txTime.IsZero() {
		txTime = time.Now().UTC()
	}

	var sentSats int64
	var receivedSats int64
	for _, vin := range tx.Vin {
		if vin.Prevout != nil && strings.EqualFold(vin.Prevout.ScriptPubKeyAddress, address) {
			sentSats += vin.Prevout.Value
		}
	}
	for _, vout := range tx.Vout {
		if strings.EqualFold(vout.ScriptPubKeyAddress, address) {
			receivedSats += vout.Value
		}
	}

	netSats := receivedSats - sentSats
	direction := "incoming"
	amountSats := netSats
	if netSats < 0 {
		direction = "outgoing"
		amountSats = -netSats
	}
	status := "pending"
	if tx.Status.Confirmed {
		status = "success"
	}
	return Transaction{
		Chain:           "bitcoin",
		Hash:            tx.TxID,
		From:            "multiple",
		To:              "multiple",
		Amount:          strconv.FormatFloat(float64(amountSats)/1e8, 'f', -1, 64),
		Symbol:          "BTC",
		ContractAddress: "native",
		Direction:       direction,
		Timestamp:       txTime,
		Status:          status,
		ExplorerURL:     ExplorerTxURL("bitcoin", tx.TxID),
	}, true
}

func getJSON(url string, dst interface{}) error {
	return getJSONWithClient(client, url, dst)
}

func getJSONWithClient(httpClient *http.Client, url string, dst interface{}) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/json,text/plain,*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if strings.Contains(strings.ToLower(strings.TrimSpace(url)), "blockscout.com") {
			req.Header.Set("Referer", "https://base.blockscout.com/")
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
					lastErr = json.NewDecoder(resp.Body).Decode(dst)
					return
				}
				lastErr = fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
				if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
					return
				}
			}()
			if lastErr == nil {
				return nil
			}
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < http.StatusInternalServerError {
				return lastErr
			}
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
		}
	}
	return lastErr
}

func fetchBlockscoutChain(chain, baseURL, address string) ([]Asset, []Transaction, error) {
	info, err := getJSONMap(baseURL + "/addresses/" + address)
	if err != nil {
		return nil, nil, err
	}

	assets := make([]Asset, 0, 16)
	if nativeRaw := blockscoutNativeRaw(info); nativeRaw != "" {
		nativeVal := decimalToFloat(nativeRaw, 18)
		assets = append(assets, Asset{
			Chain:           chain,
			ContractAddress: "native",
			Symbol:          getNativeSymbol(chain),
			BalanceStr:      nativeRaw,
			Decimals:        18,
			UIBalance:       nativeVal,
			ExplorerURL:     ExplorerAddressURL(chain, address),
		})
	}

	tokenBalances, err := getJSONSlice(baseURL + "/addresses/" + address + "/token-balances")
	if err == nil {
		for _, row := range tokenBalances {
			token, _ := row["token"].(map[string]interface{})
			if token == nil {
				continue
			}
			if typ := strings.ToLower(strings.TrimSpace(stringValue(token["type"]))); typ != "" && !strings.Contains(typ, "erc-20") {
				continue
			}
			contract := strings.TrimSpace(stringValue(token["address_hash"]))
			if contract == "" {
				continue
			}
			dec := atoiDefault(stringValue(token["decimals"]), 18)
			symbol := defaultStr(stringValue(token["symbol"]), "TOKEN")
			raw := strings.TrimSpace(stringValue(row["value"]))
			if raw == "" {
				continue
			}
			assets = append(assets, Asset{
				Chain:           chain,
				ContractAddress: contract,
				Symbol:          symbol,
				BalanceStr:      raw,
				Decimals:        dec,
				UIBalance:       decimalToFloat(raw, dec),
				ExplorerURL:     ExplorerTokenURL(chain, contract),
			})
		}
	}

	history := make([]Transaction, 0, 256)
	coinTxItems, _ := fetchBlockscoutPagedItems(baseURL+"/addresses/"+address+"/transactions", blockscoutHistoryPages)
	tokenTxItems, _ := fetchBlockscoutPagedItems(baseURL+"/addresses/"+address+"/token-transfers", blockscoutHistoryPages)
	lowerAddress := strings.ToLower(address)
	for _, entry := range coinTxItems {
		tx, _ := entry.(map[string]interface{})
		if tx == nil {
			continue
		}
		hash := strings.TrimSpace(stringValue(tx["hash"]))
		from := nestedHash(tx["from"])
		to := nestedHash(tx["to"])
		dir := direction(from, to, lowerAddress)
		if dir == "" {
			continue
		}
		value := strings.TrimSpace(stringValue(tx["value"]))
		status := normalizeStatus(stringValue(tx["status"]))
		if status == "" {
			status = "success"
		}
		history = append(history, Transaction{
			Chain:           chain,
			Hash:            hash,
			From:            from,
			To:              to,
			Amount:          formatAmountFromString(value, 18),
			Symbol:          getNativeSymbol(chain),
			ContractAddress: "native",
			Direction:       dir,
			Timestamp:       parseAnyTime(tx["timestamp"]),
			Status:          status,
			ExplorerURL:     ExplorerTxURL(chain, hash),
		})
	}
	for _, entry := range tokenTxItems {
		tx, _ := entry.(map[string]interface{})
		if tx == nil {
			continue
		}
		hash := strings.TrimSpace(stringValue(tx["transaction_hash"]))
		from := nestedHash(tx["from"])
		to := nestedHash(tx["to"])
		dir := direction(from, to, lowerAddress)
		if dir == "" {
			continue
		}
		token, _ := tx["token"].(map[string]interface{})
		if token == nil {
			continue
		}
		dec := atoiDefault(stringValue(token["decimals"]), 18)
		symbol := defaultStr(stringValue(token["symbol"]), "TOKEN")
		contract := strings.TrimSpace(stringValue(token["address_hash"]))
		amt := strings.TrimSpace(stringValue(tx["total"]))
		if amt == "" {
			amt = strings.TrimSpace(stringValue(tx["value"]))
		}
		history = append(history, Transaction{
			Chain:           chain,
			Hash:            hash,
			From:            from,
			To:              to,
			Amount:          formatAmountFromString(amt, dec),
			Symbol:          symbol,
			ContractAddress: contract,
			Direction:       dir,
			Timestamp:       parseAnyTime(tx["timestamp"]),
			Status:          "success",
			ExplorerURL:     ExplorerTxURL(chain, hash),
		})
	}

	sort.Slice(history, func(i, j int) bool {
		if history[i].Timestamp.Equal(history[j].Timestamp) {
			return history[i].Hash > history[j].Hash
		}
		return history[i].Timestamp.After(history[j].Timestamp)
	})
	if len(history) > persistedHistoryLimit {
		history = history[:persistedHistoryLimit]
	}

	return assets, history, nil
}

func fetchBlockscoutPagedItems(baseURL string, maxPages int) ([]interface{}, error) {
	if maxPages <= 0 {
		maxPages = 1
	}
	items := make([]interface{}, 0, 128)
	nextURL := baseURL
	for page := 0; page < maxPages && strings.TrimSpace(nextURL) != ""; page++ {
		resp, err := getJSONMap(nextURL)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			break
		}
		items = append(items, asSlice(resp["items"])...)
		nextParams, _ := resp["next_page_params"].(map[string]interface{})
		if len(nextParams) == 0 {
			break
		}

		u, err := url.Parse(baseURL)
		if err != nil {
			break
		}
		q := u.Query()
		for key, value := range nextParams {
			if value == nil {
				continue
			}
			q.Set(key, fmt.Sprintf("%v", value))
		}
		u.RawQuery = q.Encode()
		nextURL = u.String()
	}
	return items, nil
}

func fetchEthplorerChain(chain, baseURL, address string) ([]Asset, []Transaction, error) {
	infoURL, err := ethplorerURL(baseURL, "/getAddressInfo/"+address, nil)
	if err != nil {
		return nil, nil, err
	}
	info, err := getJSONMap(infoURL)
	if err != nil {
		return nil, nil, err
	}

	assets := make([]Asset, 0, 16)
	if nativeRaw := ethplorerNativeRaw(info, getNativeSymbol(chain)); nativeRaw != "" {
		assets = append(assets, Asset{
			Chain:           chain,
			ContractAddress: "native",
			Symbol:          getNativeSymbol(chain),
			BalanceStr:      nativeRaw,
			Decimals:        18,
			UIBalance:       decimalToFloat(nativeRaw, 18),
			ExplorerURL:     ExplorerAddressURL(chain, address),
		})
	}

	for _, item := range asSlice(info["tokens"]) {
		row, _ := item.(map[string]interface{})
		if row == nil {
			continue
		}
		tokenInfo, _ := row["tokenInfo"].(map[string]interface{})
		if tokenInfo == nil {
			continue
		}
		contract := strings.TrimSpace(stringValue(tokenInfo["address"]))
		if contract == "" {
			continue
		}
		dec := atoiDefault(stringValue(tokenInfo["decimals"]), 18)
		symbol := defaultStr(stringValue(tokenInfo["symbol"]), "TOKEN")
		raw := strings.TrimSpace(stringValue(row["rawBalance"]))
		if raw == "" {
			raw = strings.TrimSpace(stringValue(row["balance"]))
		}
		if raw == "" {
			continue
		}
		assets = append(assets, Asset{
			Chain:           chain,
			ContractAddress: contract,
			Symbol:          symbol,
			BalanceStr:      raw,
			Decimals:        dec,
			UIBalance:       decimalToFloat(raw, dec),
			ExplorerURL:     ExplorerTokenURL(chain, contract),
		})
	}

	history := make([]Transaction, 0, 64)
	coinTxURL, err := ethplorerURL(baseURL, "/getAddressTransactions/"+address, map[string]string{"limit": "100"})
	if err != nil {
		return nil, nil, err
	}
	tokenTxURL, err := ethplorerURL(baseURL, "/getAddressHistory/"+address, map[string]string{"limit": "100"})
	if err != nil {
		return nil, nil, err
	}
	coinTxs, _ := getJSONMap(coinTxURL)
	tokenTxs, _ := getJSONMap(tokenTxURL)
	history = append(history, parseEthplorerHistory(chain, address, coinTxs["operations"], true)...)
	history = append(history, parseEthplorerHistory(chain, address, coinTxs["transactions"], true)...)
	history = append(history, parseEthplorerHistory(chain, address, tokenTxs["operations"], false)...)

	return assets, history, nil
}

func ethplorerURL(baseURL, path string, extraQuery map[string]string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("ETHPLORER_API_KEY"))
	if apiKey == "" {
		return "", fmt.Errorf("missing ETHPLORER_API_KEY")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("apiKey", apiKey)
	for key, value := range extraQuery {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseEthplorerHistory(chain, address string, raw any, native bool) []Transaction {
	ops := asSlice(raw)
	if len(ops) == 0 {
		return nil
	}
	out := make([]Transaction, 0, len(ops))
	lowerAddress := strings.ToLower(strings.TrimSpace(address))
	for _, item := range ops {
		row, _ := item.(map[string]interface{})
		if row == nil {
			continue
		}
		from := strings.TrimSpace(stringValue(row["from"]))
		to := strings.TrimSpace(stringValue(row["to"]))
		dir := direction(from, to, lowerAddress)
		if dir == "" {
			continue
		}
		tokenInfo, _ := row["tokenInfo"].(map[string]interface{})
		symbol := getNativeSymbol(chain)
		contract := "native"
		dec := 18
		if !native {
			symbol = defaultStr(stringValue(tokenInfo["symbol"]), "TOKEN")
			contract = strings.TrimSpace(stringValue(tokenInfo["address"]))
			dec = atoiDefault(stringValue(tokenInfo["decimals"]), 18)
		}
		amt := strings.TrimSpace(stringValue(row["value"]))
		if amt == "" {
			amt = strings.TrimSpace(stringValue(row["rawValue"]))
		}
		out = append(out, Transaction{
			Chain:           chain,
			Hash:            strings.TrimSpace(stringValue(row["transactionHash"])),
			From:            from,
			To:              to,
			Amount:          formatAmountFromString(amt, dec),
			Symbol:          symbol,
			ContractAddress: contract,
			Direction:       dir,
			Timestamp:       parseAnyTime(row["timestamp"]),
			Status:          normalizeEthplorerStatus(stringValue(row["success"])),
			ExplorerURL:     ExplorerTxURL(chain, strings.TrimSpace(stringValue(row["transactionHash"]))),
		})
	}
	return out
}

func getJSONMap(url string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := getJSONWithClient(client, url, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func getJSONSlice(url string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	if err := getJSONWithClient(client, url, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func blockscoutNativeRaw(info map[string]interface{}) string {
	for _, key := range []string{"ETH", "BNB", "MATIC"} {
		if node, ok := info[key].(map[string]interface{}); ok {
			if raw := strings.TrimSpace(stringValue(node["rawBalance"])); raw != "" {
				return raw
			}
			if raw := strings.TrimSpace(stringValue(node["balance"])); raw != "" {
				return raw
			}
		}
	}
	if raw := strings.TrimSpace(stringValue(info["coin_balance"])); raw != "" {
		return raw
	}
	return ""
}

func decimalToFloat(raw string, decimals int) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n := new(big.Int)
	if _, ok := n.SetString(raw, 10); !ok {
		return 0
	}
	return bigIntToFloat(n, decimals)
}

func bigIntToFloat(raw *big.Int, decimals int) float64 {
	if raw == nil || raw.Sign() == 0 {
		return 0
	}
	if decimals <= 0 {
		f, _ := new(big.Float).SetInt(raw).Float64()
		return f
	}
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	rat := new(big.Rat).SetFrac(raw, divisor)
	f, _ := rat.Float64()
	return f
}

func formatAmountFromString(raw string, decimals int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "0"
	}
	n := new(big.Int)
	if _, ok := n.SetString(raw, 10); !ok {
		return "0"
	}
	return formatAmountFromBigInt(n, decimals)
}

func parseAnyTime(v interface{}) time.Time {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return time.Now()
		}
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
			if len(s) > 10 {
				return time.Unix(0, unix*int64(time.Millisecond))
			}
			return time.Unix(unix, 0)
		}
	case float64:
		unix := int64(t)
		if unix > 1e12 {
			return time.Unix(0, unix*int64(time.Millisecond))
		}
		return time.Unix(unix, 0)
	}
	return time.Now()
}

func normalizeStatus(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "1", "success", "ok", "true":
		return "success"
	case "0", "failed", "false":
		return "failed"
	default:
		return s
	}
}

func normalizeEthplorerStatus(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "1" || s == "true" {
		return "success"
	}
	if s == "0" || s == "false" {
		return "failed"
	}
	return "success"
}

func nestedHash(v interface{}) string {
	if node, ok := v.(map[string]interface{}); ok {
		if s := strings.TrimSpace(stringValue(node["hash"])); s != "" {
			return s
		}
	}
	return strings.TrimSpace(stringValue(v))
}

func atoiDefault(raw string, fallback int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return fallback
}

func defaultStr(v, fallback string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return fallback
}

func direction(from, to, addr string) string {
	if strings.EqualFold(strings.TrimSpace(from), addr) {
		return "outgoing"
	}
	if strings.EqualFold(strings.TrimSpace(to), addr) {
		return "incoming"
	}
	return ""
}

func ethplorerNativeRaw(info map[string]interface{}, nativeSymbol string) string {
	for _, key := range []string{nativeSymbol, "ETH", "BNB", "MATIC", "AVAX"} {
		if node, ok := info[key].(map[string]interface{}); ok {
			if raw := strings.TrimSpace(stringValue(node["rawBalance"])); raw != "" {
				return raw
			}
			if bal := strings.TrimSpace(stringValue(node["balance"])); bal != "" {
				return bal
			}
		}
	}
	for _, v := range info {
		if node, ok := v.(map[string]interface{}); ok {
			if raw := strings.TrimSpace(stringValue(node["rawBalance"])); raw != "" {
				return raw
			}
		}
	}
	return ""
}
