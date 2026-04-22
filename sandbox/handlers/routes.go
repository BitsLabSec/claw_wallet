package handlers

import (
	"io/fs"
	"net/http"
	"sandbox/handlers/docs"
	"sandbox/handlers/others"
)

type SandboxRoutesDeps struct {
	Auth                          func(http.HandlerFunc) http.HandlerFunc
	HandleCreate                  http.HandlerFunc
	HandleStatus                  http.HandlerFunc
	HandleBackupExport            http.HandlerFunc
	HandleZeroGRecoveryBackup     http.HandlerFunc
	HandleWalletUnlock            http.HandlerFunc
	HandleReactivate              http.HandlerFunc
	HandleBindUID                 http.HandlerFunc
	HandleWalletBind              http.HandlerFunc
	HandleWalletImport            http.HandlerFunc
	HandleWalletProvisionClaim    http.HandlerFunc
	HandleSign                    http.HandlerFunc
	HandleBroadcast               http.HandlerFunc
	HandleTransfer                http.HandlerFunc
	HandleManagedEVMInvoke        http.HandlerFunc
	HandleManagedEVMInvokeEIP1559 http.HandlerFunc
	HandleManagedSolInvoke        http.HandlerFunc
	HandleSuiExecuteTxBytes       http.HandlerFunc
	HandleSuiOptionedTx           http.HandlerFunc
	HandleUniswapSwap             http.HandlerFunc
	HandleJupiterSwap             http.HandlerFunc
	HandleCetusSwap               http.HandlerFunc
	HandleLifiBridgeQuote         http.HandlerFunc
	HandleLifiBridgeTokens        http.HandlerFunc
	HandleLifiBridge              http.HandlerFunc
	HandleLifiBridgeStatus        http.HandlerFunc
	HandleShutdown                http.HandlerFunc
	HandlePriceCache              http.HandlerFunc
	HandleOracleTestState         http.HandlerFunc
	HandleWalletRefreshAndAssets  http.HandlerFunc
	HandleAssets                  http.HandlerFunc
	HandleSecurityCache           http.HandlerFunc
	HandleWalletHistory           http.HandlerFunc
	HandleAuditLogs               http.HandlerFunc
	HandleWalletRefreshChain      http.HandlerFunc
	HandleInitialize              http.HandlerFunc
	HandleChallengeSign           http.HandlerFunc
	HandleWipe                    http.HandlerFunc
	HandleHardReset               http.HandlerFunc
	HandleLocalPolicyConfig       http.HandlerFunc
	HandleLocalPolicyUpdate       http.HandlerFunc
	HandleRPCProxy                http.HandlerFunc
	HandleSwaggerDocs             http.HandlerFunc
	HandleOpenAPISpec             http.HandlerFunc
	HandleWalletRefresh           http.HandlerFunc
	HandlePreloadSafuSkills       http.HandlerFunc
	HandleResolveSafuSkillByName  http.HandlerFunc
	HandleReadSafuSkillContent    http.HandlerFunc
	EmbeddedUI                    fs.FS
}

type route struct {
	path    string
	handler http.HandlerFunc
}

func registerRoutes(mux *http.ServeMux, routes []route) {
	for _, rt := range routes {
		mux.HandleFunc(rt.path, rt.handler)
	}
}

func InitSandboxRoutesDeps(embeddedUI fs.FS) SandboxRoutesDeps {
	return SandboxRoutesDeps{
		Auth:       auth,       //jwt-auth
		EmbeddedUI: embeddedUI, //默认网关页面
		// 逻辑路由
		HandleCreate:                  handleCreate,
		HandleStatus:                  handleStatus,
		HandleBackupExport:            handleBackupExport,
		HandleZeroGRecoveryBackup:     handleZeroGRecoveryBackup,
		HandleWalletUnlock:            handleWalletUnlock,
		HandleReactivate:              HandleReactivate,
		HandleBindUID:                 handleBindUID,
		HandleWalletBind:              handleWalletBind,
		HandleWalletImport:            handleWalletImport,
		HandleWalletProvisionClaim:    handleWalletProvisionClaim,
		HandleSign:                    handleSign,
		HandleBroadcast:               handleBroadcast,
		HandleTransfer:                handleTransfer,
		HandleManagedEVMInvoke:        HandleManagedEVMInvoke,
		HandleManagedEVMInvokeEIP1559: HandleManagedEVMInvokeEIP1559,
		HandleManagedSolInvoke:        handleManagedSolInvoke,
		HandleSuiExecuteTxBytes:       HandleSuiExecuteTxBytes,
		HandleSuiOptionedTx:           HandleSuiOptionedTx,
		HandleUniswapSwap:             handleUniswapSwap,
		HandleJupiterSwap:             handleJupiterSwap,
		HandleCetusSwap:               handleCetusSwap,
		HandleLifiBridgeQuote:         HandleLifiBridgeQuote,
		HandleLifiBridgeTokens:        HandleLifiBridgeTokens,
		HandleLifiBridge:              HandleLifiBridge,
		HandleLifiBridgeStatus:        HandleLifiBridgeStatus,
		HandleShutdown:                handleShutdown,
		HandlePriceCache:              handlePriceCache,
		HandleOracleTestState:         handleOracleTestState,
		HandleWalletRefreshAndAssets:  handleWalletRefreshAndAssets,
		HandleAssets:                  handleAssets,
		HandleSecurityCache:           handleSecurityCache,
		HandleWalletHistory:           handleWalletHistory,
		HandleAuditLogs:               handleAuditLogs,
		HandleWalletRefreshChain:      handleWalletRefreshChain,
		HandleInitialize:              HandleInitialize,
		HandleChallengeSign:           handleChallengeSign,
		HandleWipe:                    handleWipe,
		HandleHardReset:               handleHardReset,
		HandleLocalPolicyConfig:       handleLocalPolicyConfig,
		HandleLocalPolicyUpdate:       handleLocalPolicyUpdate,
		HandleRPCProxy:                handleRPCProxy,
		HandleWalletRefresh:           handleWalletRefresh,
		HandlePreloadSafuSkills:       others.HandlePreloadSafuSkills,
		HandleResolveSafuSkillByName:  others.HandleResolveSafuSkillByName,
		HandleReadSafuSkillContent:    others.HandleReadSafuSkillContent,

		//docs
		HandleSwaggerDocs: docs.HandleSwaggerDocs,
		HandleOpenAPISpec: docs.HandleOpenAPISpec,
	}
}

func RegisterSandboxRoutes(mux *http.ServeMux, deps SandboxRoutesDeps) {
	mux.HandleFunc("/api/v1/wallet/refresh/chain", deps.Auth(deps.HandleWalletRefreshChain))
	mux.HandleFunc("/api/v1/wallet/backup/0g", deps.Auth(deps.HandleZeroGRecoveryBackup))
	registerRoutes(mux, []route{
		{path: "/api/v1/wallet/init", handler: deps.Auth(deps.HandleCreate)},                             // 钱包初始化
		{path: "/api/v1/wallet/status", handler: deps.Auth(deps.HandleStatus)},                           // 钱包状态
		{path: "/api/v1/wallet/backup", handler: deps.Auth(deps.HandleBackupExport)},                     // 钱包备份导出
		{path: "/api/v1/wallet/unlock", handler: deps.Auth(deps.HandleWalletUnlock)},                     // 钱包解锁
		{path: "/api/v1/wallet/reactivate", handler: deps.Auth(deps.HandleReactivate)},                   // 钱包重激活
		{path: "/api/v1/wallet/bind_uid", handler: deps.Auth(deps.HandleBindUID)},                        // 绑定 UID
		{path: "/api/v1/wallet/bind", handler: deps.Auth(deps.HandleWalletBind)},                         // 钱包绑定
		{path: "/api/v1/wallet/import", handler: deps.Auth(deps.HandleWalletImport)},                     // 钱包导入
		{path: "/api/v1/wallet/provision", handler: deps.Auth(deps.HandleWalletProvisionClaim)},          // 预配置领取
		{path: "/api/v1/tx/sign", handler: deps.Auth(deps.HandleSign)},                                   // 通用签名
		{path: "/api/v1/tx/broadcast", handler: deps.Auth(deps.HandleBroadcast)},                         // 广播交易
		{path: "/api/v1/tx/transfer", handler: deps.Auth(deps.HandleTransfer)},                           // 转账交易
		{path: "/api/v1/tx/evm/invoke", handler: deps.Auth(deps.HandleManagedEVMInvoke)},                 // EVM 调用
		{path: "/api/v1/tx/evm/invoke_eip1559", handler: deps.Auth(deps.HandleManagedEVMInvokeEIP1559)},  // EVM EIP1559 调用
		{path: "/api/v1/tx/sol/invoke", handler: deps.Auth(deps.HandleManagedSolInvoke)},                  // Solana 调用
		{path: "/api/v1/tx/sui/execute_txbytes", handler: deps.Auth(deps.HandleSuiExecuteTxBytes)},       // Sui txBytes 执行
		{path: "/api/v1/tx/sui/execute_option", handler: deps.Auth(deps.HandleSuiOptionedTx)},            // Sui 选项执行
		{path: "/api/v1/tx/swap/evm_uniswap", handler: deps.Auth(deps.HandleUniswapSwap)},                // Uniswap 交换 目前兼容所有 Uniswap V2/V3 交换请求
		{path: "/api/v1/tx/swap/solana-jup", handler: deps.Auth(deps.HandleJupiterSwap)},                 // Jupiter 交换
		{path: "/api/v1/tx/swap/sui-cetus", handler: deps.Auth(deps.HandleCetusSwap)},                    // Cetus 交换
		{path: "/api/v1/tx/bridge/lifi/quote", handler: deps.Auth(deps.HandleLifiBridgeQuote)},           // LI.FI 报价预估
		{path: "/api/v1/tx/bridge/lifi/tokens", handler: deps.Auth(deps.HandleLifiBridgeTokens)},         // LI.FI 查询 Token 支持列表
		{path: "/api/v1/tx/bridge/lifi/execute", handler: deps.Auth(deps.HandleLifiBridge)},              // LI.FI 执行跨链
		{path: "/api/v1/tx/bridge/lifi/status", handler: deps.Auth(deps.HandleLifiBridgeStatus)},         // LI.FI 跨链状态查询
		{path: "/api/v1/sandbox/shutdown", handler: deps.Auth(deps.HandleShutdown)},                      // 关闭 sandbox
		{path: "/api/v1/price/cache", handler: deps.Auth(deps.HandlePriceCache)},                         // 价格缓存
		{path: "/api/v1/test/oracle/state", handler: deps.Auth(deps.HandleOracleTestState)},              // oracle 测试注入
		{path: "/api/v1/wallet/refreshAndAssets", handler: deps.Auth(deps.HandleWalletRefreshAndAssets)}, // 刷新并返回资产
		{path: "/api/v1/wallet/assets", handler: deps.Auth(deps.HandleAssets)},                           // 钱包资产
		{path: "/api/v1/security/cache", handler: deps.Auth(deps.HandleSecurityCache)},                   // 安全缓存
		{path: "/api/v1/wallet/history", handler: deps.Auth(deps.HandleWalletHistory)},                   // 钱包历史
		{path: "/api/v1/audit/logs", handler: deps.Auth(deps.HandleAuditLogs)},                           // 审计日志
		{path: "/api/v1/policy/local", handler: deps.Auth(deps.HandleLocalPolicyConfig)},                 // 本地策略
		{path: "/api/v1/policy/update", handler: deps.Auth(deps.HandleLocalPolicyUpdate)},                // 更新本地策略
		{path: "/api/v1/wallet/refresh", handler: deps.Auth(deps.HandleWalletRefresh)},                   // 触发钱包刷新
		{path: "/api/v1/skills/safuskill/preload", handler: deps.Auth(deps.HandlePreloadSafuSkills)},     // 预装 SafuSkill Top20
		{path: "/api/v1/skills/by-name", handler: deps.Auth(deps.HandleResolveSafuSkillByName)},          // 按名称检索并缓存 skill
		{path: "/api/v1/skills/read", handler: deps.Auth(deps.HandleReadSafuSkillContent)},               // 读取本地 skill 内容
		{path: "/wipe", handler: deps.Auth(deps.HandleWipe)},                                             // 清除本地数据
		{path: "/reset", handler: deps.Auth(deps.HandleHardReset)},                                       // 重置状态
		{path: "/api/rpc/", handler: deps.Auth(deps.HandleRPCProxy)},                                     // RPC 代理
	})

	registerRoutes(mux, []route{
		{path: "/initialize", handler: deps.HandleInitialize},        // 初始化身份
		{path: "/challenge/sign", handler: deps.HandleChallengeSign}, // 签名挑战
		{path: "/docs", handler: deps.HandleSwaggerDocs},             // Swagger 页面
		{path: "/docs/", handler: deps.HandleSwaggerDocs},            // Swagger 页面（兼容尾斜杠）
		{path: "/openapi.yaml", handler: deps.HandleOpenAPISpec},     // OpenAPI 文档
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { // 健康检查
		w.Write([]byte(`{"status": "ok"}`))
	})

	uiSubFS, _ := fs.Sub(deps.EmbeddedUI, "gateway_ui")
	mux.Handle("/", http.FileServer(http.FS(uiSubFS))) // 网关 UI 静态资源
}

// jwt 限制
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := env("AGENT_TOKEN", "")
		if token == "" {
			// If no token is configured in env, we allow it (for dev)
			next(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+token {
			http.Error(w, "Unauthorized: invalid claw wallet sandbox token", 401)
			return
		}
		next(w, r)
	}
}
