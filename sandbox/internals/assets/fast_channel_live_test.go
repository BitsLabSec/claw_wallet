package assets

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type fastChannelLiveResult struct {
	Chain        string `json:"chain"`
	Address      string `json:"address"`
	AssetCount   int    `json:"asset_count"`
	HistoryCount int    `json:"history_count"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	Error        string `json:"error,omitempty"`
}

func TestFastChannelLiveSmoke(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAY_RUN_FAST_CHANNEL_LIVE_TESTS")), "1") {
		t.Skip("set CLAY_RUN_FAST_CHANNEL_LIVE_TESTS=1 to run live fast-channel probes")
	}

	cases := []struct {
		chain   string
		address string
	}{
		{chain: "ethereum", address: strings.TrimSpace(os.Getenv("TEST_OC_ETHEREUM"))},
		{chain: "base", address: strings.TrimSpace(os.Getenv("TEST_OC_BASE"))},
		{chain: "bsc", address: strings.TrimSpace(os.Getenv("TEST_OC_BSC"))},
		{chain: "arbitrum", address: strings.TrimSpace(os.Getenv("TEST_OC_ARBITRUM"))},
		{chain: "monad", address: strings.TrimSpace(os.Getenv("TEST_OC_MONAD"))},
		{chain: "solana", address: strings.TrimSpace(os.Getenv("TEST_OC_SOLANA"))},
		{chain: "sui", address: strings.TrimSpace(os.Getenv("TEST_OC_SUI"))},
		{chain: "bitcoin", address: strings.TrimSpace(os.Getenv("TEST_OC_BITCOIN"))},
	}

	results := make([]fastChannelLiveResult, 0, len(cases))
	for _, tc := range cases {
		if tc.address == "" {
			continue
		}
		startedAt := time.Now()
		assets, history, err := FetchFreeChainData(tc.chain, tc.address)
		result := fastChannelLiveResult{
			Chain:        tc.chain,
			Address:      tc.address,
			AssetCount:   len(assets),
			HistoryCount: len(history),
			ElapsedMS:    time.Since(startedAt).Milliseconds(),
		}
		if err != nil {
			result.Error = err.Error()
			t.Errorf("%s fast channel failed: %v", tc.chain, err)
		}
		results = append(results, result)
	}

	report, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal fast channel report: %v", err)
	}
	t.Logf("fast_channel_live_results=%s", string(report))
}
