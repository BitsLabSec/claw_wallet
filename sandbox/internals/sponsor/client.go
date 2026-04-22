package sponsor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client 负责与后端代付服务通信，处理 X-402 协议
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient 创建一个 Sponsor 客户端实例
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{},
	}
}

// SponsorInfoResponse 表示 /gas-sponsor/info 接口的返回结果
type SponsorInfoResponse struct {
	ServerPublicKey  string            `json:"server_public_key"`
	SponsorAddresses map[string]string `json:"sponsor_addresses"`
}

// GetSponsorInfo 获取各链的 Sponsor 地址
func (c *Client) GetSponsorInfo() (map[string]string, error) {
	fmt.Println("sponsor.BaseURL = %s", c.BaseURL)
	resp, err := c.HTTPClient.Get(c.BaseURL + "/gas-sponsor/info")
	if err != nil {
		return nil, fmt.Errorf("failed to get sponsor info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var info SponsorInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode sponsor info: %w", err)
	}

	return info.SponsorAddresses, nil
}

// ExecuteRequest 统一的执行请求体
type ExecuteRequest struct {
	TxInfo    TxInfo     `json:"tx_info"`
	Bootstrap *Bootstrap `json:"bootstrap,omitempty"`
}

type TxInfo struct {
	Chain         string `json:"chain"`
	TxData        string `json:"tx_data"`
	UserAddress   string `json:"user_address"`
	TargetAddress string `json:"target_address"`
	UserSignature string `json:"user_signature"`
}

type Bootstrap struct {
	OriginalTxData   string `json:"original_tx_data"`
	OriginalChain    string `json:"original_chain"`
	OriginalUserAddr string `json:"original_user_addr"`
}

// EstimateResponse 402 估算返回结构
type EstimateResponse struct {
	Payment struct {
		PriceUSD uint64 `json:"price_usdc"`
	} `json:"payment"`
}

// ExecuteResponse 执行接口成功时的返回结构
type ExecuteResponse struct {
	TxHash  string `json:"tx_hash,omitempty"`
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// EstimateGas 触发 402 估算，获取所需的 USDC 费用
func (c *Client) EstimateGas(chain, originalTxBase64, userAddr, sponsorAddr string) (uint64, error) {
	reqBody := ExecuteRequest{
		TxInfo: TxInfo{
			Chain:         chain,
			TxData:        originalTxBase64,
			UserAddress:   userAddr,
			TargetAddress: sponsorAddr,
			UserSignature: "temp", // 估算阶段使用临时签名 (Demo 规范)
		},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/gas-sponsor/sponsor", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPaymentRequired { // 402
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("expected 402 for estimate, got %d: %s", resp.StatusCode, string(body))
	}

	var estResp EstimateResponse
	if err := json.NewDecoder(resp.Body).Decode(&estResp); err != nil {
		return 0, fmt.Errorf("failed to decode 402 response: %w", err)
	}

	return estResp.Payment.PriceUSD, nil
}

// SubmitBootstrapTx 提交 Bootstrap 支付交易，向 Sponsor 支付 USDC
func (c *Client) SubmitBootstrapTx(chain, paymentTxBase64, userAddr, sponsorAddr, userSig, originalTxBase64 string) (string, error) {
	reqBody := ExecuteRequest{
		TxInfo: TxInfo{
			Chain:         chain,
			TxData:        paymentTxBase64,
			UserAddress:   userAddr,
			TargetAddress: sponsorAddr,
			UserSignature: userSig,
		},
		Bootstrap: &Bootstrap{
			OriginalTxData:   originalTxBase64,
			OriginalChain:    chain,
			OriginalUserAddr: userAddr,
		},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/gas-sponsor/sponsor", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-402-Payment", "bootstrap")
	req.Header.Set("X-Payment-Chain", chain)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit bootstrap tx: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bootstrap payment failed with http status %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	var execResp ExecuteResponse
	if err := json.Unmarshal(body, &execResp); err != nil {
		return "", fmt.Errorf("failed to decode bootstrap response: %w", err)
	}
	if execResp.Status != 200 && execResp.Status != 402 {
		return "", fmt.Errorf("bootstrap payment failed with business status %d: message=%s error=%s body=%s", execResp.Status, execResp.Message, execResp.Error, string(body))
	}
	if strings.TrimSpace(execResp.TxHash) == "" {
		return "", fmt.Errorf("bootstrap payment returned empty tx hash: status=%d message=%s error=%s body=%s", execResp.Status, execResp.Message, execResp.Error, string(body))
	}
	return execResp.TxHash, nil
}

// ExecuteOriginalTx 携带支付凭证提交并执行原交易
func (c *Client) ExecuteOriginalTx(chain, originalTxBase64, userAddr, sponsorAddr, userSig, paymentTxHash string) (string, error) {
	reqBody := ExecuteRequest{
		TxInfo: TxInfo{
			Chain:         chain,
			TxData:        originalTxBase64,
			UserAddress:   userAddr,
			TargetAddress: sponsorAddr,
			UserSignature: userSig,
		},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/gas-sponsor/sponsor", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-402-Payment", paymentTxHash)
	req.Header.Set("X-Payment-Chain", chain)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute original tx: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("execute original tx failed with http status %d: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	var execResp ExecuteResponse
	if err := json.Unmarshal(body, &execResp); err != nil {
		return "", fmt.Errorf("failed to decode execute response: %w", err)
	}
	if execResp.Status != 200 && execResp.Status != 402 {
		return "", fmt.Errorf("execute original tx failed with business status %d: message=%s error=%s body=%s", execResp.Status, execResp.Message, execResp.Error, string(body))
	}
	if strings.TrimSpace(execResp.TxHash) == "" {
		return "", fmt.Errorf("execute original tx returned empty tx hash: status=%d message=%s error=%s body=%s", execResp.Status, execResp.Message, execResp.Error, string(body))
	}
	return execResp.TxHash, nil
}

// EIP2612PermitRequest EVM EIP-2612 permit 代付请求
type EIP2612PermitRequest struct {
	Chain    string `json:"chain"`
	Owner    string `json:"owner"`
	Value    string `json:"value"`
	Deadline int64  `json:"deadline"`
	V        uint8  `json:"v"`
	R        string `json:"r"`
	S        string `json:"s"`
}

// EIP2612PermitResponse EVM EIP-2612 permit 代付响应
type EIP2612PermitResponse struct {
	PermitTxHash   string `json:"permit_tx_hash"`
	TransferTxHash string `json:"transfer_tx_hash"`
	GasTxHash      string `json:"gas_tx_hash"`
	ETHSent        string `json:"eth_sent"`
	USDCCollected  string `json:"usdc_collected"`
	Status         int    `json:"status"`
	Error          string `json:"error,omitempty"`
}

// SubmitEIP2612Permit 提交 EIP-2612 permit 请求，由 sponsor 上链并收取 USDC，返回 gas_tx_hash
func (c *Client) SubmitEIP2612Permit(req EIP2612PermitRequest) (string, error) {
	body, _ := json.Marshal(req)
	resp, err := c.HTTPClient.Post(c.BaseURL+"/gas-sponsor/eip2612/permit", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("eip2612 permit request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("eip2612 permit returned %d: %s", resp.StatusCode, string(respBody))
	}

	var permitResp EIP2612PermitResponse
	if err := json.Unmarshal(respBody, &permitResp); err != nil {
		return "", fmt.Errorf("failed to decode eip2612 permit response: %w", err)
	}
	if permitResp.Status != 0 && permitResp.Status != 200 {
		return "", fmt.Errorf("eip2612 permit failed (status=%d): %s", permitResp.Status, permitResp.Error)
	}
	if strings.TrimSpace(permitResp.GasTxHash) == "" {
		return "", fmt.Errorf("eip2612 permit returned empty gas_tx_hash")
	}
	return permitResp.GasTxHash, nil
}
