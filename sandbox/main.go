package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sandbox/cli"
	"sandbox/handlers"
	"sandbox/internals/assets"
	"sandbox/internals/audit"
	gc "sandbox/internals/crypto"
	"sandbox/internals/oracle"
	"sandbox/internals/policy"
	"sandbox/internals/security"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

//go:embed gateway_ui
var embeddedUI embed.FS

var (
	sandboxServer *http.Server
	PolicyEngine  *policy.Engine
	mu            sync.RWMutex
	RelayURL      string
	EncShare1     signer.EncryptedShare
	EncShare3     signer.EncryptedShare
	MasterPubKey  string
	Addresses     map[string]string
	BoundUid      string // Persistent assigned UID attached to identity
	SekKey        []byte // Share Encryption Key (in memory, never written to disk in plaintext)
)

// BuildVersion is injected at build time via -ldflags.
var BuildVersion = "dev"

// These defaults can be overridden at build time via -ldflags -X.
var DefaultRelayURL = "https://api.clawwallet.cc"

// These defaults can be overridden at build time via -ldflags -X.
var DefaultUpgradeScriptBaseURL = "https://github.com/ClawWallet/Claw_Wallet_Bin/raw/refs/heads/main/upgrade_script"

// 兼容启动端口
const (
	defaultListenPort        = 9000
	maxListenPort            = 65535
	testRelayURL             = "https://api.bitlaptest.clawwallet.cc"
	prodRelayURL             = "https://api.clawwallet.cc"
	testUpgradeScriptBaseURL = "https://raw.githubusercontent.com/ClawWallet/Claw_Wallet_Bin/refs/heads/test/upgrade_script"
	prodUpgradeScriptBaseURL = "https://github.com/ClawWallet/Claw_Wallet_Bin/raw/refs/heads/main/upgrade_script"
)

type sandboxConfig struct {
	EnvFile          string
	RelayURL         string
	IdentityPath     string
	Share1Path       string
	Share3Path       string
	PolicyPath       string
	DailyTrackerPath string
	SecurityCache    string
	AuditPath        string
}

type identityRecord struct {
	MasterPubKey  string            `json:"master_pub_key"`
	Addresses     map[string]string `json:"addresses"`
	UID           string            `json:"uid,omitempty"`
	WrappedSEK    string            `json:"wrapped_sek,omitempty"`
	RemoteManaged bool              `json:"remote_managed,omitempty"`
	AgentToken    string            `json:"agent_token,omitempty"`
}

func main() {
	cli.BuildVersion = BuildVersion

	// cli 处理
	if handled, err := cli.RunCLI(os.Args[1:]); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	// 启动api服务
	startSandboxServer()
}

// 就是淦！ just do it!
func startSandboxServer() {
	cfg := loadSandboxConfig()
	if _, err := os.Stat(cfg.EnvFile); os.IsNotExist(err) {
		log.Println("[claw wallet sandbox] No .env.clay found. Bootstrapping new configuration...")
		bootstrapConfig(cfg.EnvFile)
	}
	_ = godotenv.Load(cfg.EnvFile)
	// 重复加载 防止bootstrapConfig之后的配置发生变化
	cfg = loadSandboxConfig()
	if runningURL, err := detectRunningSandboxFromEnvFile(cfg.EnvFile); err != nil {
		log.Printf("[claw wallet sandbox] Warning: could not probe existing sandbox from %s: %v", cfg.EnvFile, err)
	} else if runningURL != "" {
		log.Fatalf("[claw wallet sandbox] Refusing to start a second sandbox in this workspace: an existing instance is already healthy at %s (from %s). Reuse it or stop it before starting again.", runningURL, cfg.EnvFile)
	}

	RelayURL = cfg.RelayURL
	seedOracleFromEnv()

	loadedRemoteManaged := false
	if id, err := loadIdentityRecord(cfg.IdentityPath); err == nil {
		if strings.TrimSpace(id.WrappedSEK) != "" {
			if err := handlers.EnsureWrappedSEKFile(cfg.IdentityPath, id.WrappedSEK, id.AgentToken); err != nil {
				log.Printf("[claw wallet sandbox] WARNING: failed to persist wrapped_sek.json: %v", err)
			} else if id.RemoteManaged {
				id.WrappedSEK = ""
				if data, marshalErr := json.Marshal(id); marshalErr == nil {
					if err := utils.AtomicWrite(cfg.IdentityPath, data); err != nil {
						log.Printf("[claw wallet sandbox] WARNING: failed to strip wrapped_sek from identity: %v", err)
					}
				} else {
					log.Printf("[claw wallet sandbox] WARNING: failed to re-marshal sanitized identity: %v", marshalErr)
				}
			}
		}
		MasterPubKey = id.MasterPubKey
		Addresses = id.Addresses
		BoundUid = id.UID
		loadedRemoteManaged = id.RemoteManaged
		if id.RemoteManaged {
			log.Printf("[claw wallet sandbox] Remote-managed identity loaded; SEK will be resolved via PIN flow")
		} else if sek, err := handlers.LoadSEKFromIdentityOrWrappedFile(cfg.IdentityPath); err == nil {
			SekKey = sek
			log.Printf("[claw wallet sandbox] SEK loaded from identity")
		} else if err != nil {
			log.Printf("[claw wallet sandbox] WARNING: %v", err)
		}
		log.Printf("[claw wallet sandbox] Loaded identity: %s", MasterPubKey)
	}

	EncShare3 = loadEncryptedShare(cfg.Share3Path)
	EncShare1 = loadEncryptedShare(cfg.Share1Path)

	pe, err := policy.NewEngine(cfg.PolicyPath)
	if err != nil {
		log.Printf("[claw wallet sandbox] WARNING: policy init failed (path=%s): %v", cfg.PolicyPath, err)
	}
	PolicyEngine = pe

	policy.LoadTracker(cfg.DailyTrackerPath)
	security.LoadRiskCache(cfg.SecurityCache)
	audit.Init(cfg.AuditPath)

	// 基本上配置已经加载完咯 ⬆️⬆️⬆️⬆️⬆️⬆️
	// 下面就是逻辑咯 ⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️
	handlers.ApplyRuntimeState(handlers.RuntimeState{
		PolicyEngine:         PolicyEngine,
		Mu:                   &mu,
		RelayURL:             RelayURL,
		EncShare1:            EncShare1,
		EncShare3:            EncShare3,
		MasterPubKey:         MasterPubKey,
		Addresses:            Addresses,
		BoundUid:             BoundUid,
		SekKey:               SekKey,
		RemoteManaged:        loadedRemoteManaged,
		BuildVersion:         BuildVersion,
		UpgradeScriptBaseURL: defaultUpgradeScriptBaseURL(),
	})
	handlers.TriggerStartupAssetRefresh()
	// 启动时检查一次版本更新（非强制，失败不影响正常使用，后续定时检查）
	handlers.TriggerStartupVersionCheck()

	oracle.StartAutoRefresh() // 价格自动刷新
	assets.StartAutoRefresh(func() map[string]string {
		return handlers.SnapshotAddresses()
	})

	go handlers.ActivationLoop()        // 激活循环
	go handlers.LocalMigrationLoop()    // 本地迁移循环
	go handlers.RestoreLoop()           // 恢复循环
	go handlers.ProvisionedUnlockLoop() // 预解锁循环
	go handlers.ControlPlaneLoop()      // 控制平面循环
	go handlers.SignSessionLoop()       // 签名会话循环

	// api server 启动
	mux := http.NewServeMux()
	handlers.RegisterSandboxRoutes(mux, handlers.InitSandboxRoutesDeps(embeddedUI))
	addr, errPick := findFreeListenAddr(9000)
	if errPick != nil {
		log.Fatalf("[claw wallet sandbox] No free listen port: %v", errPick)
	}
	if err := mergeEnvClayListenInfo(cfg.EnvFile, addr); err != nil {
		log.Printf("[claw wallet sandbox] Warning: could not update %s with listen info: %v", cfg.EnvFile, err)
	}
	sandboxServer = &http.Server{
		Addr:    addr,
		Handler: withCORS(mux),
	}
	// 使用结构体注入的方式 保证全局控制相同
	handlers.ApplyRuntimeState(handlers.RuntimeState{
		SandboxServer:        sandboxServer,
		PolicyEngine:         PolicyEngine,
		Mu:                   &mu,
		RelayURL:             RelayURL,
		EncShare1:            EncShare1,
		EncShare3:            EncShare3,
		MasterPubKey:         MasterPubKey,
		Addresses:            Addresses,
		BoundUid:             BoundUid,
		SekKey:               SekKey,
		RemoteManaged:        loadedRemoteManaged,
		BuildVersion:         BuildVersion,
		UpgradeScriptBaseURL: defaultUpgradeScriptBaseURL(),
	})
	// TODO:后续考虑三方sdk的日志debug-----
	log.Printf("[claw wallet sandbox] Version %s listening on %s (written to %s as LISTEN_ADDR / CLAY_SANDBOX_URL)", BuildVersion, addr, cfg.EnvFile)
	docsBase := addr
	if strings.HasPrefix(docsBase, ":") {
		docsBase = "127.0.0.1" + docsBase
	}
	log.Printf("[claw wallet sandbox] Swagger UI: http://%s/docs | OpenAPI: http://%s/openapi.yaml", docsBase, docsBase)
	if err := sandboxServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadSandboxConfig() sandboxConfig {
	return sandboxConfig{
		EnvFile:          env("CLAY_ENV_FILE", ".env.clay"),
		RelayURL:         env("RELAY_URL", defaultRelayURL()),
		IdentityPath:     env("IDENTITY_PATH", "identity.json"),
		Share1Path:       env("SHARE1_PATH", "share1.json"),
		Share3Path:       env("SHARE3_PATH", "share3.json"),
		PolicyPath:       env("POLICY_PATH", "policy.json"),
		DailyTrackerPath: env("DAILY_TRACKER_PATH", "daily_tracker.json"),
		SecurityCache:    env("SECURITY_CACHE_PATH", "security_cache.json"),
		AuditPath:        env("AUDIT_PATH", "audit.jsonl"),
	}
}

// 判定identity是否村庄
func loadIdentityRecord(identityPath string) (identityRecord, error) {
	data, err := os.ReadFile(identityPath)
	if err != nil {
		return identityRecord{}, err
	}
	var id identityRecord
	if err := json.Unmarshal(data, &id); err != nil {
		return identityRecord{}, err
	}
	return id, nil
}

// 读取identity.json
func unwrapSEKFromIdentity(id identityRecord, identityPath string) ([]byte, error) {
	if strings.TrimSpace(id.WrappedSEK) == "" {
		return nil, errors.New("identity.json does not contain wrapped_sek")
	}
	agentToken := strings.TrimSpace(env("AGENT_TOKEN", ""))
	if agentToken == "" {
		agentToken = strings.TrimSpace(id.AgentToken)
	}
	kek := gc.DeriveKEK(agentToken, identityPath)
	sek, err := gc.UnwrapSEK(id.WrappedSEK, kek)
	if err != nil {
		return nil, fmt.Errorf("sek unwrap failed: %w", err)
	}
	return sek, nil
}

func ensureRemoteManagedWrappedSEK(identityPath string, id identityRecord) error {
	agentToken := strings.TrimSpace(env("AGENT_TOKEN", ""))
	if agentToken == "" {
		agentToken = strings.TrimSpace(id.AgentToken)
	}
	newSEK, err := gc.GenerateSEK()
	if err != nil {
		return fmt.Errorf("generate policy sek: %w", err)
	}
	wrappedSEK, err := gc.WrapSEK(newSEK, gc.DeriveKEK(agentToken, identityPath))
	if err != nil {
		return fmt.Errorf("wrap policy sek: %w", err)
	}
	payload := map[string]any{
		"master_pub_key": id.MasterPubKey,
		"addresses":      id.Addresses,
		"uid":            id.UID,
		"wrapped_sek":    wrappedSEK,
		"remote_managed": true,
		"agent_token":    agentToken,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode identity with regenerated wrapped_sek: %w", err)
	}
	if err := utils.AtomicWrite(identityPath, data); err != nil {
		return fmt.Errorf("persist regenerated wrapped_sek: %w", err)
	}
	return nil
}

// 读取oracle相关配置
func seedOracleFromEnv() {
	raw := strings.TrimSpace(env("CLAY_ORACLE_SNAPSHOT_JSON", ""))
	if raw == "" {
		return
	}
	snapshot := map[string]float64{}
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		log.Printf("[claw wallet sandbox] Ignoring invalid CLAY_ORACLE_SNAPSHOT_JSON: %v", err)
		return
	}
	oracle.RestoreForTest(snapshot)
	log.Printf("[claw wallet sandbox] Seeded oracle snapshot from environment with %d entries", len(snapshot))
}

// cors 跨域
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		requestHeaders := r.Header.Get("Access-Control-Request-Headers")
		if requestHeaders == "" {
			requestHeaders = "Origin, Content-Type, Accept, Authorization, X-Requested-With"
		}
		w.Header().Set("Access-Control-Allow-Headers", requestHeaders)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// 如果配置文件不存在 则初始化配置文件
func bootstrapConfig(path string) {
	token := ""
	relay := defaultRelayURL()
	upgradeScriptBaseURL := defaultUpgradeScriptBaseURL()

	// Port is chosen at server start; LISTEN_ADDR / CLAY_SANDBOX_URL are written then (informational).
	config := fmt.Sprintf(`# LISTEN_ADDR and CLAY_SANDBOX_URL are written when the server starts (informational).
CLAY_RELAY_URL=%s
RELAY_URL=%s
AGENT_TOKEN=%s
CLAY_AGENT_TOKEN=%s
UPGRADE_SCRIPT_BASE_URL=%s

# 0G recovery backup defaults to testnet to keep initial usage low-cost.
# Set CLAY_0G_NETWORK=mainnet to switch the backup flow to 0G mainnet.
CLAY_0G_NETWORK=testnet
CLAY_0G_STORAGE_RPC=
CLAY_0G_STORAGE_INDEXER=
CLAY_0G_RECOVERY_VAULT_ADDRESS=

# Optional per-chain Alchemy RPC endpoints used by sandbox asset refresh / RPC proxy.
# Example:
# CLAY_ALCHEMY_RPC_ETHEREUM=https://eth-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_BASE=https://base-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_ARBITRUM=https://arb-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_OPTIMISM=https://opt-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_POLYGON=https://polygon-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_BSC=https://bnb-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_SOLANA=https://solana-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_SUI=https://sui-mainnet.g.alchemy.com/v2/your-key
# CLAY_ALCHEMY_RPC_TEMPO=https://tempo-moderato.g.alchemy.com/v2/your-key

# Third-party API keys. Leave empty unless you need those integrations.
JUPITER_API_KEY=
UNISWAP_TRADE_API_KEY=
ETHPLORER_API_KEY=
MONADSCAN_API_KEY=
MONADSCAN_FALLBACK_API_KEY=
`, relay, relay, token, token, upgradeScriptBaseURL)

	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		log.Printf("[claw wallet sandbox] Failed to write bootstrap config: %v", err)
	}

	log.Printf("[claw wallet sandbox] New environment bootstrapped: %s", path)
	log.Printf("[claw wallet sandbox] AGENT_TOKEN left empty by default for local access.")
	log.Printf("[claw wallet sandbox] Listen port will be chosen at server start (from 9000).")
}

func bootstrapDefaults() (relayURL, upgradeScriptBaseURL string) {
	version := strings.ToLower(strings.TrimSpace(BuildVersion))
	if version == "" || version == "dev" || strings.Contains(version, "test") || env("CLAY_ENABLE_TEST_ENDPOINTS", "") == "1" {
		return testRelayURL, testUpgradeScriptBaseURL
	}
	return prodRelayURL, prodUpgradeScriptBaseURL
}

// 控制sanbox启动端口
func findFreeListenAddr(startPort int) (string, error) {
	if startPort < 1 || startPort > maxListenPort {
		startPort = defaultListenPort
	}
	for port := startPort; port <= maxListenPort; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return addr, nil
		}
	}
	// 没有合适的启动端口-理论上不存在
	return "", errors.New("no free TCP port found on 127.0.0.1 (9000-65535)")
}

func mergeEnvClayListenInfo(path, listenAddr string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	set := map[string]string{
		"LISTEN_ADDR":      listenAddr,
		"CLAY_SANDBOX_URL": "http://" + listenAddr,
	}
	content := utils.MergeEnvKV(string(data), set, []string{"LISTEN_ADDR", "CLAY_SANDBOX_URL"})
	return utils.AtomicWrite(path, []byte(content))
}

// 助手函数 ⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️===
func detectRunningSandboxFromEnvFile(path string) (string, error) {
	values, err := godotenv.Read(path)
	if err != nil {
		return "", err
	}
	baseURL := normalizeSandboxBaseURL(strings.TrimSpace(values["CLAY_SANDBOX_URL"]))
	if baseURL == "" {
		baseURL = normalizeSandboxBaseURL(strings.TrimSpace(values["LISTEN_ADDR"]))
	}
	if baseURL == "" {
		return "", nil
	}

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/health", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" && !strings.Contains(trimmed, `"ok"`) {
		return "", nil
	}
	return baseURL, nil
}

func normalizeSandboxBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return strings.TrimRight(raw, "/")
	}
	if strings.HasPrefix(raw, ":") {
		raw = "127.0.0.1" + raw
	}
	return "http://" + strings.TrimRight(raw, "/")
}

func loadEncryptedShare(path string) signer.EncryptedShare {
	var share signer.EncryptedShare
	data, err := os.ReadFile(path)
	if err != nil {
		return share
	}
	_ = json.Unmarshal(data, &share)
	return share
}

func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func defaultRelayURL() string {
	if v := strings.TrimSpace(DefaultRelayURL); v != "" {
		return v
	}
	return "https://api.clawwallet.cc"
}

func defaultUpgradeScriptBaseURL() string {
	if v := strings.TrimSpace(DefaultUpgradeScriptBaseURL); v != "" {
		return v
	}
	return "https://github.com/ClawWallet/Claw_Wallet_Bin/raw/refs/heads/main/upgrade_script"
}
