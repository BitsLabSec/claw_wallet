package assets

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type testJSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type testJSONRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

func serveTestJSONRPC(t *testing.T, w http.ResponseWriter, r *http.Request, respond func(testJSONRPCRequest) testJSONRPCResponse) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		t.Fatal("empty payload")
	}

	if trimmed[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			t.Fatalf("decode batch payload: %v", err)
		}
		responses := make([]testJSONRPCResponse, 0, len(raws))
		for _, raw := range raws {
			var req testJSONRPCRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Fatalf("decode batch request: %v", err)
			}
			responses = append(responses, respond(req))
		}
		data, err := json.Marshal(responses)
		if err != nil {
			t.Fatalf("marshal batch response: %v", err)
		}
		_, _ = w.Write(data)
		return
	}

	var req testJSONRPCRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	data, err := json.Marshal(respond(req))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	_, _ = w.Write(data)
}
