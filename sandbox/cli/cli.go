package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

var BuildVersion = "dev"

func RunCLI(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	switch args[0] {
	case "serve":
		return false, nil
	case "help", "--help", "-h":
		printCLIHelp()
		return true, nil
	case "version", "verison", "--version", "-v":
		fmt.Println(BuildVersion)
		return true, nil
	case "health":
		return true, cliPrintLocalAPI("/health")
	case "status":
		short := len(args) > 1 && (args[1] == "--short" || args[1] == "-s")
		return true, runStatusCLI(short)
	case "addresses":
		return true, runAddressesCLI()
	case "history":
		return true, runHistoryCLI(args[1:])
	case "backup":
		return true, cliPrintLocalAPI("/api/v1/wallet/backup")
	case "backup0g", "backup-0g":
		return true, runOptionalPayloadCLI(args[1:], http.MethodPost, "/api/v1/wallet/backup/0g", "backup0g [file.json|-]")
	case "init":
		return true, runOptionalPayloadCLI(args[1:], http.MethodPost, "/api/v1/wallet/init", "init [file.json|-]")
	case "unlock":
		return true, runUnlockCLI(args[1:])
	case "refreshAndAssets":
		return true, cliPrintLocalAPI("/api/v1/wallet/refreshAndAssets")
	case "refreshChain", "refresh-chain":
		return true, runRefreshChainCLI(args[1:])
	case "assets":
		return true, cliPrintLocalAPI("/api/v1/wallet/assets")
	case "prices":
		return true, cliPrintLocalAPI("/api/v1/price/cache")
	case "security":
		return true, cliPrintLocalAPI("/api/v1/security/cache")
	case "refresh":
		return true, cliPostLocalAPI("/api/v1/wallet/refresh", nil)
	case "reactivate":
		return true, cliPostLocalAPI("/api/v1/wallet/reactivate", nil)
	case "stop", "shutdown":
		return true, cliPostLocalAPI("/api/v1/sandbox/shutdown", nil)
	case "audit":
		limit := "50"
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			limit = strings.TrimSpace(args[1])
		}
		return true, cliPrintLocalAPI("/api/v1/audit/logs?limit=" + url.QueryEscape(limit))
	case "policy":
		return true, runPolicyCLI(args[1:])
	case "sign":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/sign", "sign <file.json|->")
	case "broadcast":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/broadcast", "broadcast <file.json|->")
	case "transfer":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/transfer", "transfer <file.json|->")
	case "evmInvoke", "evm-invoke":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/evm/invoke", "evmInvoke <file.json|->")
	case "evmInvokeEIP1559", "evm-invoke-eip1559":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/evm/invoke_eip1559", "evmInvokeEIP1559 <file.json|->")
	case "suiExecuteTxBytes", "sui-execute-txbytes":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/sui/execute_txbytes", "suiExecuteTxBytes <file.json|->")
	case "suiExecuteOption", "sui-execute-option":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/sui/execute_option", "suiExecuteOption <file.json|->")
	case "evmUniswap", "evm-uniswap", "uniswap":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/swap/evm_uniswap", "evmUniswap <file.json|->")
	case "solanaJup", "solana-jup", "jupiter":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/swap/solana-jup", "solanaJup <file.json|->")
	case "suiCetus", "sui-cetus", "cetus":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/swap/sui-cetus", "suiCetus <file.json|->")
	case "lifiQuote", "lifi-quote":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/bridge/lifi/quote", "lifiQuote <file.json|->")
	case "lifiExecute", "lifi-execute":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/bridge/lifi/execute", "lifiExecute <file.json|->")
	case "lifiStatus", "lifi-status":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/tx/bridge/lifi/status", "lifiStatus <file.json|->")
	case "import":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/api/v1/wallet/import", "import <file.json|->")
	case "provision":
		return true, runProvisionCLI(args[1:])
	case "bindUID", "bind_uid", "bind-uid":
		return true, runBindUIDCLI(args[1:])
	case "bind":
		return true, runBindCLI(args[1:])
	case "bridge-tokens":
		return true, runBridgeTokensCLI(args[1:])
	case "bridge-quote":
		return true, runBridgeQuoteCLI(args[1:])
	case "bridge-execute":
		return true, runBridgeExecuteCLI(args[1:])
	case "bridge-status":
		return true, runBridgeStatusCLI(args[1:])
	case "wipe":
		return true, cliPostLocalAPI("/wipe", nil)
	case "reset":
		return true, cliPostLocalAPI("/reset", nil)
	case "oracleTestState", "oracle-test-state":
		return true, runOracleTestStateCLI(args[1:])
	case "skills":
		return true, runSkillsCLI(args[1:])
	case "rpc":
		return true, runRPCCLI(args[1:])
	case "initialize":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/initialize", "initialize <file.json|->")
	case "challengeSign", "challenge-sign":
		return true, runPayloadCLI(args[1:], http.MethodPost, "/challenge/sign", "challengeSign <file.json|->")
	case "api":
		return true, runAPICLI(args[1:])
	default:
		return true, fmt.Errorf("unknown command %q - run with help, -h, or --help for usage", args[0])
	}
}

func runRefreshChainCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("usage: refreshChain <chain>")
	}
	chain := strings.ToLower(strings.TrimSpace(args[0]))
	return cliPostLocalAPI("/api/v1/wallet/refresh/chain", map[string]string{"chain": chain})
}

func runPolicyCLI(args []string) error {
	if len(args) == 0 || args[0] == "get" {
		return cliPrintLocalAPI("/api/v1/policy/local")
	}
	if args[0] == "update" || args[0] == "set" {
		return runPayloadCLI(args[1:], http.MethodPost, "/api/v1/policy/update", "policy update <file.json|->")
	}
	return fmt.Errorf("unknown policy command %q (supported: get, update)", args[0])
}

func runProvisionCLI(args []string) error {
	if len(args) < 2 {
		return errors.New("provision requires a uid and otp")
	}
	body, _ := json.Marshal(map[string]string{
		"uid": strings.TrimSpace(args[0]),
		"otp": strings.TrimSpace(args[1]),
	})
	return cliPostLocalAPI("/api/v1/wallet/provision", json.RawMessage(body))
}

func runBindCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("bind requires message_hash_hex\n  usage: <binary> bind <message_hash_hex>")
	}
	body, _ := json.Marshal(map[string]string{"message_hash_hex": strings.TrimSpace(args[0])})
	return cliPostLocalAPI("/api/v1/wallet/bind", json.RawMessage(body))
}

func runBindUIDCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("bindUID requires uid\n  usage: <binary> bindUID <uid>")
	}
	body, _ := json.Marshal(map[string]string{"uid": strings.TrimSpace(args[0])})
	return cliPostLocalAPI("/api/v1/wallet/bind_uid", json.RawMessage(body))
}

func runUnlockCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("unlock requires pin\n  usage: <binary> unlock <pin>")
	}
	body, _ := json.Marshal(map[string]string{"pin": strings.TrimSpace(args[0])})
	return cliPostLocalAPI("/api/v1/wallet/unlock", json.RawMessage(body))
}

func runOracleTestStateCLI(args []string) error {
	if len(args) == 0 {
		return cliPrintLocalAPI("/api/v1/test/oracle/state")
	}
	return runPayloadCLI(args, http.MethodPost, "/api/v1/test/oracle/state", "oracleTestState [file.json|-]")
}

func runSkillsCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("skills requires a subcommand: preload | by-name <name> | read <name>")
	}
	switch args[0] {
	case "preload":
		return cliPostLocalAPI("/api/v1/skills/safuskill/preload", nil)
	case "by-name":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("skills by-name requires a name")
		}
		return cliPrintLocalAPI("/api/v1/skills/by-name?name=" + url.QueryEscape(strings.TrimSpace(args[1])))
	case "read":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("skills read requires a name")
		}
		return cliPrintLocalAPI("/api/v1/skills/read?name=" + url.QueryEscape(strings.TrimSpace(args[1])))
	default:
		return fmt.Errorf("unknown skills command %q (supported: preload, by-name, read)", args[0])
	}
}

func runRPCCLI(args []string) error {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" {
		return errors.New("rpc requires a chain and payload file\n  usage: <binary> rpc <chain> <file.json|->")
	}
	chain := strings.Trim(strings.TrimSpace(args[0]), "/")
	return runPayloadCLI(args[1:], http.MethodPost, "/api/rpc/"+chain, "rpc <chain> <file.json|->")
}

func runAPICLI(args []string) error {
	if len(args) < 2 {
		return errors.New("api requires method and path\n  usage: <binary> api <get|post|put|patch|delete> <path> [file.json|-]")
	}
	method := strings.ToUpper(strings.TrimSpace(args[0]))
	path := strings.TrimSpace(args[1])
	if path == "" || !strings.HasPrefix(path, "/") {
		return errors.New("api path must start with '/'")
	}

	switch method {
	case http.MethodGet:
		if len(args) > 2 {
			return errors.New("api get does not take a payload")
		}
		return cliPrintLocalAPI(path)
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return runOptionalPayloadCLI(args[2:], method, path, "api <method> <path> [file.json|-]")
	default:
		return fmt.Errorf("unsupported api method %q", method)
	}
}

func runPayloadCLI(args []string, method, path, usage string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s requires a payload file or '-'\n  usage: <binary> %s", strings.Fields(usage)[0], usage)
	}
	if len(args) > 1 {
		return fmt.Errorf("too many arguments\n  usage: <binary> %s", usage)
	}
	data, contentType, err := readPayloadArg(args[0])
	if err != nil {
		return err
	}
	return cliSendLocalAPI(method, path, data, contentType)
}

func runOptionalPayloadCLI(args []string, method, path, usage string) error {
	if len(args) == 0 {
		return cliSendLocalAPI(method, path, nil, "application/json")
	}
	if len(args) > 1 {
		return fmt.Errorf("too many arguments\n  usage: <binary> %s", usage)
	}
	data, contentType, err := readPayloadArg(args[0])
	if err != nil {
		return err
	}
	return cliSendLocalAPI(method, path, data, contentType)
}

func readPayloadArg(arg string) ([]byte, string, error) {
	var (
		data []byte
		err  error
	)
	if arg == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(arg)
	}
	if err != nil {
		return nil, "", err
	}
	return data, detectContentType(data), nil
}

func detectContentType(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "application/json"
	}
	if json.Valid(trimmed) {
		return "application/json"
	}
	return "text/plain"
}

func printCLIHelp() {
	fmt.Print(`Claw Wallet Sandbox - local CLI for the HTTP API

  Run from the directory that contains .env.clay (next to identity.json). The CLI loads it for
  LISTEN_ADDR / CLAY_SANDBOX_URL (informational; updated when the server starts) and optional
  AGENT_TOKEN (Bearer). Running the binary with no args starts the HTTP server (same role as "serve").
  Payload commands accept <file.json|->. Use "-" to read from stdin. JSON vs text/plain is auto-detected.

Usage - replace <bin> with your executable name (e.g. clay-sandbox-windows-amd64.exe):

  <bin> help | -h | --help
      Show this text.
  <bin> version | verison | --version | -v
      Print the current build version.

  Server
  <bin> serve
      Start the HTTP sandbox in the foreground (blocks until exit).
  <bin> health
      GET /health - basic liveness probe.
  <bin> stop
  <bin> shutdown
      POST /api/v1/sandbox/shutdown - stop the sandbox process.

  Wallet (read)
  <bin> status [--short|-s]
      GET wallet status JSON; --short prints a one-line summary.
  <bin> addresses
      Print the address map from status.
  <bin> history [chain] [limit]
      Transaction history; optional chain filter and limit.
  <bin> backup
      GET /api/v1/wallet/backup - export current local identity/share/policy snapshot.
  <bin> backup0g [file.json|-]
      POST /api/v1/wallet/backup/0g - upload SEK-encrypted share2/share3 to 0G Storage and register RecoveryVault receipts. Optional JSON can override rpc_url, indexer_url, vault_address.
  <bin> assets
      GET cached multichain balances.
  <bin> refreshAndAssets
      GET refresh + asset snapshot (stronger than assets alone).
  <bin> prices
      Oracle price cache.
  <bin> security
      Risk/security cache snapshot.
  <bin> audit [limit]
      Audit log entries (default limit 50).

  Wallet (write)
  <bin> init [file.json|-]
      POST /api/v1/wallet/init. Optional JSON body, e.g. {"master_pin":"123456"}.
  <bin> unlock <pin>
      POST /api/v1/wallet/unlock using {"pin":"..."} for imported/provisioned wallets.
  <bin> refresh
      Trigger async balance refresh.
  <bin> reactivate
      Reactivate local wallet (SEK path); not for remote-managed flows.
  <bin> import <file.json|->
      POST wallet import JSON from file or stdin.
  <bin> provision <uid> <otp>
      POST provision with uid and one-time password.
  <bin> bindUID <uid>
      POST /api/v1/wallet/bind_uid to persist a relay-assigned UID into identity.json.
  <bin> bind <message_hash_hex>
      POST bind with message_hash_hex (hex string).
  <bin> wipe
      POST /wipe - clear only the in-memory signer session.
  <bin> reset
      POST /reset - hard reset local identity/share files and memory.

  Transactions
  <bin> sign <file.json|->
      POST /api/v1/tx/sign - generic transaction/message signing request.
  <bin> broadcast <file.json|->
      Broadcast signed raw transaction JSON.
  <bin> transfer <file.json|->
      POST transfer request JSON.
  <bin> evmInvoke <file.json|->
      POST /api/v1/tx/evm/invoke - legacy gas-price EVM contract call.
  <bin> evmInvokeEIP1559 <file.json|->
      POST /api/v1/tx/evm/invoke_eip1559 - EIP-1559 EVM contract call.
  <bin> suiExecuteTxBytes <file.json|->
      POST /api/v1/tx/sui/execute_txbytes. Accepts JSON or quoted raw string payload.
  <bin> suiExecuteOption <file.json|->
      POST /api/v1/tx/sui/execute_option for Haedal/Cetus option-driven actions.
  <bin> evmUniswap <file.json|->
      POST /api/v1/tx/swap/evm_uniswap.
  <bin> solanaJup <file.json|->
      POST /api/v1/tx/swap/solana-jup.
  <bin> suiCetus <file.json|->
      POST /api/v1/tx/swap/sui-cetus.
  <bin> lifiQuote <file.json|->
      POST /api/v1/tx/bridge/lifi/quote.
  <bin> lifiExecute <file.json|->
      POST /api/v1/tx/bridge/lifi/execute.
  <bin> lifiStatus <file.json|->
      POST /api/v1/tx/bridge/lifi/status.

  Cross-Chain (LI.FI Bridge)
  ** Flow Requirement: 1) bridge-tokens -> 2) bridge-quote -> 3) bridge-execute
  ** For EVM to Sui routes, you can set "via_solana": true in the JSON to use a faster route (2 mins vs 15 mins).
  <bin> bridge-tokens <chains>
      GET supported tokens for chains (comma-separated, e.g. 1,56,137).
  <bin> bridge-quote <file.json|->
      POST cross-chain bridge quote estimation request JSON.
  <bin> bridge-execute <file.json|->
      POST execute a cross-chain bridge request JSON.
  <bin> bridge-status <uid>
      POST check the status of an async bridge task.

  Policy
  <bin> policy get
      GET local policy.json via /api/v1/policy/local.
  <bin> policy update <file.json|->
      POST /api/v1/policy/update with a partial or full policy JSON payload.

  Skills
  <bin> skills preload
      POST /api/v1/skills/safuskill/preload to download/cache the default SafuSkill set.
  <bin> skills by-name <name>
      GET /api/v1/skills/by-name?name=... to fetch/cache one skill by name.
  <bin> skills read <name>
      GET /api/v1/skills/read?name=... to read a cached local skill.

  Control / Internal
  <bin> oracleTestState
      GET /api/v1/test/oracle/state (dev/test only when enabled).
  <bin> oracleTestState <file.json|->
      POST /api/v1/test/oracle/state with {"forced_unavailable":...,"snapshot":...}.
  <bin> initialize <file.json|->
      POST /initialize for legacy installer/bootstrap identity setup.
  <bin> challengeSign <file.json|->
      POST /challenge/sign for legacy active-signer challenge signing.
  <bin> rpc <chain> <file.json|->
      POST /api/rpc/{chain} to proxy a raw JSON-RPC request body upstream.
  <bin> api <get|post|put|patch|delete> <path> [file.json|-]
      Low-level escape hatch for any local sandbox path, e.g. api get /api/v1/wallet/status.

HTTP docs (browser): http://<host>:<port>/docs - use LISTEN_ADDR or CLAY_SANDBOX_URL from .env.clay after the server has started (first free port from 9000 on 127.0.0.1). Use the same AGENT_TOKEN in Authorize when required.

`)
}

func runBridgeTokensCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("bridge-tokens requires chains (comma-separated)\n  usage: <binary> bridge-tokens <chains>")
	}
	return cliPrintLocalAPI("/api/v1/tx/bridge/lifi/tokens?chains=" + url.QueryEscape(strings.TrimSpace(args[0])))
}

func runBridgeQuoteCLI(args []string) error {
	if len(args) < 1 {
		return errors.New("bridge-quote requires a JSON file path")
	}

	var (
		data []byte
		err  error
	)
	if args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		return err
	}
	return cliPostLocalAPI("/api/v1/tx/bridge/lifi/quote", json.RawMessage(data))
}

func runBridgeExecuteCLI(args []string) error {
	if len(args) < 1 {
		return errors.New("bridge-execute requires a JSON file path")
	}

	var (
		data []byte
		err  error
	)
	if args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		return err
	}
	return cliPostLocalAPI("/api/v1/tx/bridge/lifi/execute", json.RawMessage(data))
}

func runBridgeStatusCLI(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("bridge-status requires a uid\n  usage: <binary> bridge-status <uid>")
	}
	body, _ := json.Marshal(map[string]string{"uid": strings.TrimSpace(args[0])})
	return cliPostLocalAPI("/api/v1/tx/bridge/lifi/status", json.RawMessage(body))
}

func localAPIBaseURL() string {
	addr := env("LISTEN_ADDR", "127.0.0.1:9000")
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/")
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + strings.TrimRight(addr, "/")
}

func cliPrintLocalAPI(path string) error {
	body, err := callLocalAPI(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	fmt.Println(body)
	return nil
}

func cliPostLocalAPI(path string, payload interface{}) error {
	body, err := callLocalAPI(http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	fmt.Println(body)
	return nil
}

func cliSendLocalAPI(method, path string, payload []byte, contentType string) error {
	body, err := callLocalAPIBytes(method, path, payload, contentType)
	if err != nil {
		return err
	}
	fmt.Println(body)
	return nil
}

func callLocalAPI(method, path string, payload interface{}) (string, error) {
	var data []byte
	if payload != nil {
		switch v := payload.(type) {
		case json.RawMessage:
			data = []byte(v)
		case []byte:
			data = v
		default:
			encoded, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			data = encoded
		}
	}
	return callLocalAPIBytes(method, path, data, "application/json")
}

func callLocalAPIBytes(method, path string, payload []byte, contentType string) (string, error) {
	envFile := ".env.clay"
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return "", err
	}
	_ = godotenv.Load(envFile)

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, localAPIBaseURL()+path, body)
	if err != nil {
		return "", err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	if token := env("AGENT_TOKEN", ""); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("claw wallet sandbox API unavailable at %s: %w", localAPIBaseURL(), err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		trimmed = "{}"
	}

	var formatted bytes.Buffer
	if json.Indent(&formatted, []byte(trimmed), "", "  ") == nil {
		trimmed = formatted.String()
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s %s failed: %s", method, path, trimmed)
	}
	return trimmed, nil
}

func runStatusCLI(short bool) error {
	body, err := callLocalAPI(http.MethodGet, "/api/v1/wallet/status", nil)
	if err != nil {
		return err
	}
	if !short {
		fmt.Println(body)
		return nil
	}

	var status struct {
		Status        string            `json:"status"`
		LockedReason  string            `json:"locked_reason"`
		UID           string            `json:"uid"`
		Addresses     map[string]string `json:"addresses"`
		TodaySpentUSD float64           `json:"today_spent_usd"`
		TodayTxCount  int               `json:"today_tx_count"`
	}
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		fmt.Println(body)
		return nil
	}

	if status.LockedReason != "" {
		fmt.Printf("status=%s locked_reason=%s uid=%s today_spent_usd=%.2f today_tx_count=%d\n", status.Status, status.LockedReason, status.UID, status.TodaySpentUSD, status.TodayTxCount)
	} else {
		fmt.Printf("status=%s uid=%s today_spent_usd=%.2f today_tx_count=%d\n", status.Status, status.UID, status.TodaySpentUSD, status.TodayTxCount)
	}
	for chain, addr := range status.Addresses {
		fmt.Printf("%s=%s\n", chain, addr)
	}
	return nil
}

func runAddressesCLI() error {
	body, err := callLocalAPI(http.MethodGet, "/api/v1/wallet/status", nil)
	if err != nil {
		return err
	}

	var status struct {
		Addresses map[string]string `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		fmt.Println(body)
		return nil
	}

	formatted, _ := json.MarshalIndent(status.Addresses, "", "  ")
	fmt.Println(string(formatted))
	return nil
}

func runHistoryCLI(args []string) error {
	path := "/api/v1/wallet/history"
	params := url.Values{}
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		params.Set("chain", strings.TrimSpace(args[0]))
	}
	if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
		params.Set("limit", strings.TrimSpace(args[1]))
	}
	if encoded := params.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return cliPrintLocalAPI(path)
}

func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}
