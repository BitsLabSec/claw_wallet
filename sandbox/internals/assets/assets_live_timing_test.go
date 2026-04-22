package assets

import (
	"os"
	"testing"
	"time"
)

const liveTimingAddress = "0x0000000000000000000000000000000000000001"

func TestLiveMeasureZeroGAndMonadTimings(t *testing.T) {
	if os.Getenv("CLAY_LIVE_RPC_TIMING") != "1" {
		t.Skip("set CLAY_LIVE_RPC_TIMING=1 to run live 0g/monad timing checks")
	}

	cases := []struct {
		name  string
		chain string
	}{
		{name: "0g", chain: "0g"},
		{name: "monad", chain: "monad"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := assetRPCURLs(tc.chain)
			if len(endpoints) == 0 {
				t.Fatalf("expected endpoints for %s", tc.chain)
			}

			fullStartedAt := time.Now()
			assets, history, err := fetchEVMChainDataWithFallback(tc.chain, endpoints, liveTimingAddress)
			fullElapsed := time.Since(fullStartedAt).Round(time.Millisecond)
			t.Logf("%s full refresh path took %s (assets=%d history=%d)", tc.chain, fullElapsed, len(assets), len(history))
			if err != nil {
				t.Fatalf("%s full refresh failed after %s: %v", tc.chain, fullElapsed, err)
			}

			historyStartedAt := time.Now()
			historyOnly, err := fetchHistoryOnlyWithFallback(tc.chain, liveTimingAddress, usageFactsHistoryLimit)
			historyElapsed := time.Since(historyStartedAt).Round(time.Millisecond)
			t.Logf("%s history-only path took %s (txs=%d)", tc.chain, historyElapsed, len(historyOnly))
			if err != nil {
				t.Fatalf("%s history-only refresh failed after %s: %v", tc.chain, historyElapsed, err)
			}
		})
	}
}
