package assets

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestFetchStandardEVMHistoryIncludesIncomingNativeTransfers(t *testing.T) {
	const (
		address = "0xabc0000000000000000000000000000000000001"
		from    = "0xfeedface00000000000000000000000000000001"
		hash    = "0xincoming"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTestJSONRPC(t, w, r, func(req testJSONRPCRequest) testJSONRPCResponse {
			switch req.Method {
			case "eth_blockNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x14"}
			case "eth_getTransactionCount":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0"}
			case "eth_getBlockByNumber":
				params := req.Params
				blockNum := parseTestHexInt(strings.TrimSpace(params[0].(string)))
				full := false
				if len(params) > 1 {
					full, _ = params[1].(bool)
				}
				block := map[string]any{
					"timestamp":    "0x" + strconv.FormatInt(int64(1_700_000_000+blockNum), 16),
					"transactions": []any{},
				}
				if blockNum == 8 && full {
					block["timestamp"] = "0x6566e100"
					block["transactions"] = []any{
						map[string]any{
							"hash":  hash,
							"from":  from,
							"to":    address,
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
				t.Fatalf("unexpected rpc method %s", req.Method)
				return testJSONRPCResponse{}
			}
		})
	}))
	defer server.Close()

	rows, err := fetchStandardEVMHistory("base", []string{server.URL}, address, 10)
	if err != nil {
		t.Fatalf("fetchStandardEVMHistory returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 history row, got %d", len(rows))
	}
	if rows[0].Hash != hash || rows[0].Direction != "incoming" || rows[0].To != address {
		t.Fatalf("unexpected history row: %+v", rows[0])
	}
}

func parseTestHexInt(raw string) int {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return 0
	}
	value, _ := strconv.ParseInt(raw, 16, 64)
	return int(value)
}
