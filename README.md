# Claw Wallet Sandbox

## 项目简介
Claw Wallet Sandbox 是一个本地运行的多链钱包沙盒服务，负责在用户设备内完成密钥分片管理、签名、交易构造辅助、资产查询、风控策略执行和审计记录。

它对外同时提供两种使用方式：

- 本地 HTTP API，适合桌面端、浏览器端或其他程序接入
- 内置 CLI，适合终端用户和调试场景

项目的核心安全思路是：

- 私钥种子不会以明文长期落盘
- 使用 Shamir Secret Sharing 对密钥进行拆分
- 签名和恢复流程依赖本地分片、PIN 和策略校验
- 敏感操作会记录到本地审计日志

## 主要能力
- 多链钱包能力：支持 EVM 系链、Solana、Sui、Tron、Bitcoin
- 多种交易入口：签名、广播、转账、合约调用
- DeFi 集成：Uniswap、Jupiter、Cetus、LI.FI Bridge
- 本地风控：限额、策略更新、审计日志、风险缓存
- 本地资产能力：余额、历史、价格缓存、链上刷新
- 0G Recovery Backup：将恢复材料加密后上传到 0G Storage，并向 RecoveryVault 注册收据

## 支持的典型链
- EVM：`ethereum`、`0g`、`base`、`bsc`、`arbitrum`、`optimism`、`polygon`、`avalanche`、`linea`、`zksync`、`monad`、`tempo`、`kite`、`sepolia`
- 其他：`solana`、`sui`、`tron`、`bitcoin`

## 快速开始

### 1. 编译
在 [main.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/main.go) 所在目录执行：

```bash
go build -o clay-sandbox .
```

### 2. 启动
直接运行可执行文件即可启动本地服务：

```bash
./clay-sandbox serve
```

如果不带参数直接运行二进制，默认也是启动服务。

首次启动时，程序会自动生成 `.env.clay`，并把当前监听地址写入：

- `LISTEN_ADDR`
- `CLAY_SANDBOX_URL`

默认会从 `127.0.0.1:9000` 开始寻找可用端口。

### 3. 查看 API 文档
服务启动后，可以在浏览器打开：

```text
http://127.0.0.1:<端口>/docs
```

或者读取 `.env.clay` 里的 `CLAY_SANDBOX_URL` 后访问：

```text
${CLAY_SANDBOX_URL}/docs
```

OpenAPI 原始文件地址：

```text
${CLAY_SANDBOX_URL}/openapi.yaml
```

## 常见使用流程

### 初始化钱包
```bash
./clay-sandbox init
```

也可以传入 JSON：

```bash
./clay-sandbox init wallet-init.json
```

### 查看状态
```bash
./clay-sandbox status
./clay-sandbox status --short
```

### 解锁钱包
```bash
./clay-sandbox unlock 123456
```

### 查看地址与资产
```bash
./clay-sandbox addresses
./clay-sandbox assets
./clay-sandbox refreshAndAssets
```

### 导出本地备份
```bash
./clay-sandbox backup
```

### 通用签名 / 广播
```bash
./clay-sandbox sign sign.json
./clay-sandbox broadcast rawtx.json
```

### 转账与链上调用
```bash
./clay-sandbox transfer transfer.json
./clay-sandbox evmInvoke call.json
./clay-sandbox evmInvokeEIP1559 call-1559.json
./clay-sandbox suiExecuteTxBytes sui-tx.json
```

### Swap / Bridge
```bash
./clay-sandbox evmUniswap swap.json
./clay-sandbox solanaJup swap.json
./clay-sandbox suiCetus swap.json

./clay-sandbox lifiQuote quote.json
./clay-sandbox lifiExecute bridge.json
./clay-sandbox lifiStatus status.json
```

### 策略与审计
```bash
./clay-sandbox policy get
./clay-sandbox policy update policy.json
./clay-sandbox audit 100
```

## 0G 备份说明

`/api/v1/wallet/backup/0g` 和 CLI 的 `backup0g` 命令会执行以下动作：

- 读取当前本地恢复材料
- 使用本地 SEK 进行加密封装
- 上传 `share2`、`share3` 到 0G Storage
- 将生成的收据注册到 0G RecoveryVault

对应 CLI：

```bash
./clay-sandbox backup0g
```

也支持传入 JSON 覆盖当前配置：

```json
{
  "rpc_url": "https://evmrpc-testnet.0g.ai",
  "indexer_url": "https://indexer-storage-testnet-turbo.0g.ai",
  "vault_address": "0x254bfe1433C4C10d05cD37B6eF3F062323FC6be5"
}
```

## 0G 测试网 / 主网切换

现在 0G 备份网络已经支持直接通过 `.env.clay` 切换。

默认配置是测试网，原因很简单：大部分用户刚开始没有主网资产，测试网更适合先跑通流程。

### 默认行为
如果你不改配置，Sandbox 会默认使用：

- `CLAY_0G_NETWORK=testnet`
- `rpc_url = https://evmrpc-testnet.0g.ai`
- `indexer_url = https://indexer-storage-testnet-turbo.0g.ai`
- `vault_address = 0x254bfe1433C4C10d05cD37B6eF3F062323FC6be5`

### 切换到主网
把 `.env.clay` 改成：

```dotenv
CLAY_0G_NETWORK=mainnet
```

此时会自动切换到主网默认值：

- `rpc_url = https://evmrpc.0g.ai`
- `indexer_url = https://indexer-storage-turbo.0g.ai`
- `vault_address = 0xa8DF92c6724Db748B82d90f50b4b1e1542175440`

### 精细覆盖
如果你希望指定自己的 0G 节点或自定义 RecoveryVault 地址，也可以在 `.env.clay` 里单独写：

```dotenv
CLAY_0G_STORAGE_RPC=https://evmrpc-testnet.0g.ai
CLAY_0G_STORAGE_INDEXER=https://indexer-storage-testnet-turbo.0g.ai
CLAY_0G_RECOVERY_VAULT_ADDRESS=0x254bfe1433C4C10d05cD37B6eF3F062323FC6be5
```

优先级如下：

- 请求体里的 `rpc_url` / `indexer_url` / `vault_address`
- `.env.clay` 中的 `CLAY_0G_STORAGE_RPC` / `CLAY_0G_STORAGE_INDEXER` / `CLAY_0G_RECOVERY_VAULT_ADDRESS`
- `CLAY_0G_NETWORK` 对应的默认网络配置

## 0G 测试网水龙头
如果你要体验 0G 测试网备份，通常需要一点测试网 Gas。

官方水龙头可以从这里进入：

- [https://faucet.0g.ai](https://faucet.0g.ai)

建议流程：

1. 先准备一个你的测试地址
2. 去水龙头领取测试币
3. 把 `.env.clay` 保持在 `CLAY_0G_NETWORK=testnet`
4. 执行 `./clay-sandbox backup0g`

## Alchemy RPC 配置

之前某些 Alchemy RPC 入口是硬编码在代码中的，现在已经改成完全从环境变量读取。

这意味着：

- Sandbox 不再内置任何默认 Alchemy RPC
- 如果你不配置，系统会回退到公共 RPC 或项目已有的公共节点列表
- 如果你想使用自己的 Alchemy 节点，需要在 `.env.clay` 中按链填写完整 URL

### 可配置的环境变量

示例：

```dotenv
CLAY_ALCHEMY_RPC_ETHEREUM=https://eth-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_BASE=https://base-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_ARBITRUM=https://arb-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_OPTIMISM=https://opt-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_POLYGON=https://polygon-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_BSC=https://bnb-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_SOLANA=https://solana-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_SUI=https://sui-mainnet.g.alchemy.com/v2/your-key
CLAY_ALCHEMY_RPC_TEMPO=https://tempo-moderato.g.alchemy.com/v2/your-key
```

### 什么时候建议配置 Alchemy
- 你希望更稳定的资产刷新速度
- 你在公共 RPC 上频繁遇到限流
- 你希望 RPC Proxy 固定走你自己的服务商

### 关闭 Alchemy
如果你已经设置了 Alchemy RPC，但想临时禁用，可以设置：

```dotenv
CLAY_DISABLE_ALCHEMY=1
```

## `.env.clay` 示例
一个更适合新用户的最小配置如下：

```dotenv
RELAY_URL=https://api.clawwallet.cc
AGENT_TOKEN=
CLAY_0G_NETWORK=testnet

# 只有在你需要自定义 0G 节点时才填写
CLAY_0G_STORAGE_RPC=
CLAY_0G_STORAGE_INDEXER=
CLAY_0G_RECOVERY_VAULT_ADDRESS=

# 只有在你需要自定义 Alchemy 时才填写
CLAY_ALCHEMY_RPC_ETHEREUM=
CLAY_ALCHEMY_RPC_BASE=
CLAY_ALCHEMY_RPC_ARBITRUM=
CLAY_ALCHEMY_RPC_OPTIMISM=
CLAY_ALCHEMY_RPC_POLYGON=
CLAY_ALCHEMY_RPC_BSC=
CLAY_ALCHEMY_RPC_SOLANA=
CLAY_ALCHEMY_RPC_SUI=
CLAY_ALCHEMY_RPC_TEMPO=
```

## 重要本地文件
Sandbox 会在当前工作目录维护一些本地状态文件：

- `.env.clay`：运行配置
- `identity.json`：身份、公钥、UID 等信息
- `share1.json`
- `share3.json`
- `policy.json`
- `daily_tracker.json`
- `security_cache.json`
- `audit.jsonl`

这些文件里有的钱包恢复信息和策略信息非常敏感，请务必妥善保存。

## 安全提示
- 不要把 `share1.json`、`share3.json`、PIN 发给任何人
- 不要把生产用 RPC key 直接写到会公开提交的仓库里
- 如果是首次体验，优先使用测试网跑通完整流程
- 备份、恢复、策略更新前，先确认当前 `.env.clay` 指向的是你期望的网络

## 代码入口
如果你准备继续开发，几个最值得先看的入口如下：

- 启动入口：[main.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/main.go)
- 路由注册：[routes.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/handlers/routes.go)
- CLI 入口：[cli.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/cli/cli.go)
- 0G 备份实现：[backup_0g.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/handlers/backup_0g.go)
- 资产与 RPC 选择逻辑：[assets.go](file:///d:/_Work/Safe/0g_hack_wallet/_backup/sandbox/internals/assets/assets.go)
