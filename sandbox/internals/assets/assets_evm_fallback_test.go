package assets

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchEVMChainDataWithFallbackForArbitrum(t *testing.T) {
	const address = "0x0000000000000000000000000000000000000001"
	t.Setenv(disableExplorerFallbackEnv, "1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTestJSONRPC(t, w, r, func(req testJSONRPCRequest) testJSONRPCResponse {
			switch req.Method {
			case "eth_getBalance":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0xde0b6b3a7640000"}
			case "alchemy_getTokenBalances":
				return testJSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   map[string]any{"code": -32601, "message": "alchemy token balances unavailable"},
				}
			case "alchemy_getAssetTransfers":
				return testJSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   map[string]any{"code": -32601, "message": "alchemy transfers unavailable"},
				}
			case "eth_blockNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x10"}
			case "eth_getTransactionCount":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0"}
			case "eth_getBlockByNumber":
				params := req.Params
				blockNum := parseTestHexInt(params[0].(string))
				block := map[string]any{
					"timestamp":    "0x" + "6566e100",
					"transactions": []any{},
				}
				if blockNum == 8 {
					block["transactions"] = []any{
						map[string]any{
							"hash":  "0xincoming",
							"from":  "0xfeedface00000000000000000000000000000001",
							"to":    "0xabc0000000000000000000000000000000000001",
							"nonce": "0x0",
							"value": "0x29a2241af62c0000",
						},
					}
				}
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: block}
			case "eth_getTransactionReceipt":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"status": "0x1"}}
			case "eth_getLogs":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: []any{}}
			default:
				t.Fatalf("unexpected method %v", req.Method)
				return testJSONRPCResponse{}
			}
		})
	}))
	defer server.Close()

	assets, history, err := fetchEVMChainDataWithFallback("arbitrum", []string{server.URL}, address)
	if err != nil {
		t.Fatalf("fetchEVMChainDataWithFallback returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].Chain != "arbitrum" || assets[0].ContractAddress != "native" || assets[0].BalanceStr != "1000000000000000000" {
		t.Fatalf("unexpected assets: %+v", assets)
	}
	if len(history) != 0 {
		t.Fatalf("expected empty history fallback, got %+v", history)
	}
}
