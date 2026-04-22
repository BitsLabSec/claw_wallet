package security

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TokenRisk struct {
	RiskLevel int      `json:"risk_level"` // 1-4
	RiskLabel string   `json:"risk_label"`
	Risks     []string `json:"risks"`
	FetchedAt time.Time
}

var (
	riskCache = make(map[string]TokenRisk)
	mu        sync.RWMutex
	client    = &http.Client{Timeout: 10 * time.Second}
	savePath  = "security_cache.json"
)

func LoadRiskCache(path string) {
	if path != "" {
		savePath = path
	}
	data, err := os.ReadFile(savePath)
	if err != nil {
		return
	}
	mu.Lock()
	json.Unmarshal(data, &riskCache)
	mu.Unlock()
	log.Printf("[security] Loaded %d cached risk entries", len(riskCache))
}

func saveRiskCache() {
	mu.RLock()
	data, err := json.MarshalIndent(riskCache, "", "  ")
	mu.RUnlock()
	if err == nil {
		os.WriteFile(savePath, data, 0644)
	}
}

var chainToID = map[string]int{
	"ethereum": 1,
	"0g":       16661,
	"arbitrum": 42161,
	"bsc":      56,
	"base":     8453,
	"kite":     2366,
	"tempo":    42431,
	"solana":   501,
	"sui":      784,
}

func CheckTokenRisk(chain, contract string) TokenRisk {
	if contract == "native" {
		return TokenRisk{RiskLevel: 1, RiskLabel: "Safe", Risks: []string{}, FetchedAt: time.Now()}
	}

	chainID, ok := chainToID[strings.ToLower(chain)]
	if !ok {
		return TokenRisk{RiskLevel: 1, RiskLabel: "Unknown Chain", FetchedAt: time.Now()}
	}

	key := fmt.Sprintf("%d:%s", chainID, strings.ToLower(contract))

	mu.RLock()
	cached, found := riskCache[key]
	mu.RUnlock()

	if found && time.Since(cached.FetchedAt) < 1*time.Hour {
		return cached
	}

	// Fetch from OKX
	risk := fetchOKXRisk(chainID, contract)

	mu.Lock()
	riskCache[key] = risk
	mu.Unlock()

	go saveRiskCache()

	return risk
}

func fetchOKXRisk(chainID int, contract string) TokenRisk {
	url := fmt.Sprintf("https://web3.okx.com/priapi/v1/dx/market/v2/risk/new/check?chainId=%d&tokenContractAddress=%s", chainID, contract)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[security] OKX Risk Check failed: %v", err)
		return TokenRisk{RiskLevel: 0, RiskLabel: "Detection Failed", FetchedAt: time.Now()}
	}
	defer resp.Body.Close()

	var res struct {
		Code int `json:"code"`
		Data struct {
			RiskLevel   string `json:"riskLevel"`
			BuyTaxes    string `json:"buyTaxes"`
			SellTaxes   string `json:"sellTaxes"`
			AllAnalysis struct {
				HighRiskList []struct {
					RiskKey  string `json:"riskKey"`
					RiskName string `json:"riskName"`
				} `json:"highRiskList"`
			} `json:"allAnalysis"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return TokenRisk{RiskLevel: 0, RiskLabel: "Decode Error", FetchedAt: time.Now()}
	}

	// 1. Initial level from OKX (1-4)
	okxLevel := 1
	if res.Data.RiskLevel != "" {
		fmt.Sscanf(res.Data.RiskLevel, "%d", &okxLevel)
	}

	// 2. Extract specific risks
	isHoneypot := false
	isAirdrop := false
	for _, r := range res.Data.AllAnalysis.HighRiskList {
		if r.RiskKey == "isHoneypot" {
			isHoneypot = true
		}
		if r.RiskKey == "isRubbishAirdrop" {
			isAirdrop = true
		}
	}

	// 3. Parse Taxes
	buyTax := parseTax(res.Data.BuyTaxes)
	sellTax := parseTax(res.Data.SellTaxes)

	// 4. Calculate our "Actionable" level
	// Final Level 4 = BLOCKING
	// High OKX risk (Level 4) is downgraded to Warning (Level 3)
	// UNLESS it meets the user's specific blocking criteria.
	finalLevel := okxLevel
	if okxLevel >= 4 {
		finalLevel = 3
	}

	// Elevate to Level 4 ONLY for specific user-requested triggers
	if isHoneypot || isAirdrop || buyTax > 10.0 || sellTax > 10.0 {
		finalLevel = 4
	}

	label := "Safe"
	if finalLevel >= 4 {
		label = "High Risk"
		if isHoneypot {
			label = "Honeypot"
		}
		if isAirdrop {
			label = "Scam Airdrop"
		}
		if buyTax > 10 || sellTax > 10 {
			label = "High Tax"
		}
	} else if finalLevel == 3 {
		label = "Warning"
	} else if finalLevel == 2 {
		label = "Attention"
	}

	log.Printf("[security] Risk for %s: ActionLevel=%d (OKX=%d, Tax=%.1f/%.1f, Honey=%v, Air=%v)",
		contract, finalLevel, okxLevel, buyTax, sellTax, isHoneypot, isAirdrop)

	return TokenRisk{
		RiskLevel: finalLevel,
		RiskLabel: label,
		FetchedAt: time.Now(),
	}
}

func parseTax(s string) float64 {
	if s == "" {
		return 0
	}
	// OKX sometimes returns "0.00%" or "100.00"
	s = strings.TrimSuffix(s, "%")
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return val
}

func Snapshot() map[string]TokenRisk {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]TokenRisk)
	for k, v := range riskCache {
		out[k] = v
	}
	return out
}
