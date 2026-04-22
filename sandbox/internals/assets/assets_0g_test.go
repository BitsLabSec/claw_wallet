package assets

import (
	"os"
	"strings"
	"testing"
)

func TestZeroGAssetRPCURLsPreferAnkrThenOfficial(t *testing.T) {
	t.Setenv("CLAY_RPC_0G", "")

	urls := assetRPCURLs("0g")
	if len(urls) < 2 {
		t.Fatalf("expected 0g rpc fallback list, got %v", urls)
	}
	if urls[0] != zeroGAnkrRPC {
		t.Fatalf("expected Ankr 0g rpc first, got %v", urls)
	}
	if urls[1] != zeroGOfficialRPC {
		t.Fatalf("expected official 0g rpc second, got %v", urls)
	}
}

func TestZeroGAssetRPCEndpointsRespondWithChainID(t *testing.T) {
	if strings.TrimSpace(os.Getenv("CLAY_ENABLE_LIVE_RPC_TESTS")) != "1" {
		t.Skip("set CLAY_ENABLE_LIVE_RPC_TESTS=1 to run live 0g RPC integration checks")
	}
	t.Setenv("CLAY_RPC_0G", "")

	for _, endpoint := range []string{zeroGAnkrRPC, zeroGOfficialRPC} {
		res, err := rpcCall(endpoint, "eth_chainId", []interface{}{})
		if err != nil {
			t.Fatalf("eth_chainId failed for %s: %v", endpoint, err)
		}
		got, _ := res["result"].(string)
		if got != "0x4115" {
			t.Fatalf("eth_chainId(%s) = %q, want 0x4115", endpoint, got)
		}
	}
}
