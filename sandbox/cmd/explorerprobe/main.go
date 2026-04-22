package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sandbox/internals/assets"
	"strings"
	"time"
)

type probeTarget struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
	URL     string `json:"url,omitempty"`
}

type probeResult struct {
	Chain          string `json:"chain"`
	Address        string `json:"address"`
	URL            string `json:"url"`
	FinalURL       string `json:"final_url,omitempty"`
	StatusCode     int    `json:"status_code"`
	ContentType    string `json:"content_type,omitempty"`
	ElapsedMS      int64  `json:"elapsed_ms"`
	BodyBytes      int    `json:"body_bytes"`
	Title          string `json:"title,omitempty"`
	AddressFound   bool   `json:"address_found"`
	KeywordFound   bool   `json:"keyword_found"`
	CloudflareHint bool   `json:"cloudflare_hint"`
	Error          string `json:"error,omitempty"`
}

type probeReport struct {
	GeneratedAt string        `json:"generated_at"`
	Targets     []probeTarget `json:"targets"`
	Results     []probeResult `json:"results"`
}

var (
	titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spacePattern = regexp.MustCompile(`\s+`)
)

func main() {
	timeout := flag.Duration("timeout", 20*time.Second, "per-request timeout")
	outputPath := flag.String("output", "", "optional JSON report output path")
	targetsPath := flag.String("targets", "", "optional JSON file with [{\"chain\":\"...\",\"address\":\"...\"}]")
	flag.Parse()

	targets, err := loadTargets(*targetsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load targets: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			req.Header.Set("User-Agent", browserUserAgent())
			req.Header.Set("Accept", browserAcceptHeader())
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			return nil
		},
	}

	report := probeReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Targets:     targets,
		Results:     make([]probeResult, 0, len(targets)),
	}
	for _, target := range targets {
		report.Results = append(report.Results, probeExplorer(client, target))
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(*outputPath) != "" {
		if err := os.WriteFile(*outputPath, encoded, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println(string(encoded))
}

func loadTargets(path string) ([]probeTarget, error) {
	if strings.TrimSpace(path) == "" {
		return defaultTargets(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []probeTarget
	if err := json.Unmarshal(raw, &targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func defaultTargets() []probeTarget {
	const evmAddress = "0xf9cbd837a4bff3c0e48ac108f8d19d663a99ede8"
	return []probeTarget{
		{Chain: "ethereum", Address: evmAddress},
		{Chain: "0g", Address: evmAddress},
		{Chain: "base", Address: evmAddress},
		{Chain: "bsc", Address: evmAddress},
		{Chain: "arbitrum", Address: evmAddress},
		{Chain: "monad", Address: "0xf4c6940cea946f9df0361bc4c733878107326def", URL: "https://monadscan.com/address/0xf4c6940cea946f9df0361bc4c733878107326def"},
		{Chain: "solana", Address: "A7Rtw6KYrThh6F4fVXYsTsYjJS6g1gVVT2oL85PHnzU3"},
		{Chain: "sui", Address: "0x46fd0e512fdd1da8a0ed6f9c3c5ad0b989fc06ccf2e5a9804c502901662a8d77", URL: "https://suiscan.xyz/mainnet/account/0x46fd0e512fdd1da8a0ed6f9c3c5ad0b989fc06ccf2e5a9804c502901662a8d77"},
		{Chain: "bitcoin", Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
	}
}

func probeExplorer(client *http.Client, target probeTarget) probeResult {
	url := strings.TrimSpace(target.URL)
	if url == "" {
		url = assets.ExplorerAddressURL(target.Chain, target.Address)
	}
	result := probeResult{
		Chain:   target.Chain,
		Address: target.Address,
		URL:     url,
	}
	if strings.TrimSpace(url) == "" {
		result.Error = "no explorer url configured"
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", browserUserAgent())
	req.Header.Set("Accept", browserAcceptHeader())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	started := time.Now()
	resp, err := client.Do(req)
	result.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if readErr != nil {
		result.Error = readErr.Error()
	}
	bodyText := string(body)

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.ContentType = resp.Header.Get("Content-Type")
	result.BodyBytes = len(body)
	result.Title = extractTitle(bodyText)
	result.AddressFound = pageContainsAddress(bodyText, target.Address)
	result.KeywordFound = pageContainsKeyword(bodyText, target.Chain)
	result.CloudflareHint = strings.Contains(strings.ToLower(bodyText), "cloudflare") || strings.Contains(strings.ToLower(bodyText), "attention required")
	return result
}

func extractTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(spacePattern.ReplaceAllString(match[1], " "))
}

func pageContainsAddress(body, address string) bool {
	bodyLower := strings.ToLower(body)
	addrLower := strings.ToLower(strings.TrimSpace(address))
	if addrLower == "" {
		return false
	}
	if strings.Contains(bodyLower, addrLower) {
		return true
	}
	if strings.HasPrefix(addrLower, "0x") && len(addrLower) > 10 {
		short := addrLower[:10]
		return strings.Contains(bodyLower, short)
	}
	if len(addrLower) > 12 {
		return strings.Contains(bodyLower, addrLower[:6]) && strings.Contains(bodyLower, addrLower[len(addrLower)-6:])
	}
	return false
}

func pageContainsKeyword(body, chain string) bool {
	bodyLower := strings.ToLower(body)
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "solana":
		return strings.Contains(bodyLower, "solana") || strings.Contains(bodyLower, "solscan")
	case "sui":
		return strings.Contains(bodyLower, "sui") || strings.Contains(bodyLower, "suivision")
	case "bitcoin":
		return strings.Contains(bodyLower, "bitcoin") || strings.Contains(bodyLower, "mempool")
	case "monad":
		return strings.Contains(bodyLower, "monad")
	case "0g":
		return strings.Contains(bodyLower, "0g") || strings.Contains(bodyLower, "chainscan")
	default:
		return strings.Contains(bodyLower, "address") || strings.Contains(bodyLower, "transactions")
	}
}

func browserUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
}

func browserAcceptHeader() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}
