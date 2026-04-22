package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sandbox/internals/audit"
	"sandbox/internals/policy"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
	"time"

	suiclient "github.com/block-vision/sui-go-sdk/sui"
	suitypes "github.com/coming-chat/go-sui/v2/sui_types"
	"github.com/fardream/go-bcs/bcs"
)

// TODO:如果后续文件增长 考虑加入到handlers/sui下进行模块划分

const haedalSkillUrl = "https://skillsapi.haedal.xyz/"
const cetusSkillUrl = "https://skillsapi.cetus.io/"

var haSuiNodeIds = []string{
	"0xd939e3fe7ea4d503f84767dca0c58b7ec1c71f085638a4c0611aa64aa71b5fcf",
	"0x00ae78d3e5ba5d6b8de32455474f52811b95617cbad39ebf4f9e2daf67187407",
	"0xa2bf32db91ad54684cfd8a4e1d85f7672875d62421d40a8d993f601cff9b61ff",
	"0xc8a57a7ae3b814afc15a907d963a288454b2c0f1a323fd556cb2d56d85a94583",
	"0x4fffd0005522be4bc029724c7f0f6ed7093a6bf3a09b90e62f61dc15181e1a3e",
}

var haWalNodeIds = []string{
	"0x7b3ba6de2ae58283f60d5b8dc04bb9e90e4796b3b2e0dea75569f491275242e7",
	"0x67fd6f33aec6efb51edb7336809cc64061ac288062e0ce8f63cce1b90c310fc5",
	"0x69c4793731a971d5652e99cc34e9714e6ebb7a29576ac4469d13acdc722a0f15",
	"0x555f07999a9b95af4750c530e2a77c4733055975438ce627857ee75134320b3c",
	"0x298868c0219260012465c21933a552a776e5cb188113db209cf30d2d9228c176",
	"0x610e4dafe91d26f03b149b2b5bd7f5aa15ff1da6036c13517f078b67096a1547",
	"0x0c86e9b7b48ede6c487a7a2ba5fb37cbfe86e9d022afb7448b0de9f45eea1bdd",
	"0x7c09670cbf67f4a9213177364c6b70bac7922d21affd0ea88450270c43d3587a",
	"0x60e667d1fb3bda30811339f253c485024bcff82284856322d0be73020aa4038b",
	"0x0db16ea0fcc2ff37a76ceb249ce4a91b6c5426b965f922c6eb1bcf351a861432",
}

var haedalOptionsUrlList = map[string]string{
	"hasui_stake":                       "api/v1/hasui/stake",                       //质押hasui
	"hasui_withdraw_instant":            "api/v1/hasui/withdraw_instant",            //即时提取hasui
	"hasui_withdraw":                    "api/v1/hasui/withdraw",                    //普通提取hasui
	"hasui_claim":                       "api/v1/hasui/claim",                       //领取hasui奖励
	"hawal_stake":                       "api/v1/hawal/stake",                       //质押hawal
	"hawal_withdraw_instant":            "api/v1/hawal/withdraw_instant",            //即时提取hawal
	"hawal_withdraw":                    "api/v1/hawal/withdraw",                    //普通提取hawal
	"hawal_claim":                       "api/v1/hawal/claim",                       //领取hawal奖励
	"vehaedal_add_stake":                "api/v1/vehaedal/add_stake",                //质押vehaedal
	"vehaedal_add_to_existing_stake":    "api/v1/vehaedal/add_to_existing_stake",    //追加质押vehaedal
	"vehaedal_extend_existing_lock":     "api/v1/vehaedal/extend_existing_lock",     //延长锁定期vehaedal
	"vehaedal_start_decay":              "api/v1/vehaedal/start_decay",              //开始衰减vehaedal
	"vehaedal_stop_decay":               "api/v1/vehaedal/stop_decay",               //停止衰减vehaedal
	"vehaedal_unstake_and_claim":        "api/v1/vehaedal/unstake_and_claim",        //解除质押并领取vehaedal
	"vehaedal_claim_rewards_v2":         "api/v1/vehaedal/claim_rewards_v2",         //领取vehaedal奖励v2版本（需要传period参数）
	"vehaedal_claim_rewards_v2_epoch_1": "api/v1/vehaedal/claim_rewards_v2_epoch_1", //领取vehaedal奖励v2版本（固定领取第一轮奖励）
}

var cetusOptionsUrlList = map[string]string{
	"swapa2b": "api/v1/cetus/swap1",
	"swapb2a": "api/v1/cetus/swap2",
}

// 方案1 直接签名txbytes 注意风险控制
func HandleSuiExecuteTxBytes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		http.Error(w, "txbytes is required", http.StatusBadRequest)
		return
	}

	var req HaedalTxBytesExecuteRequest
	if raw[0] == '{' {
		if err := json.Unmarshal(raw, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	} else if raw[0] == '"' {
		var tx string
		if err := json.Unmarshal(raw, &tx); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.TxBytes = tx
	} else {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	base64Candidate := strings.TrimSpace(req.TxBytesBase64)
	if base64Candidate == "" {
		base64Candidate = strings.TrimSpace(req.TxBytes)
	}

	txBytesBase64, err := ResolveBase64OrHexPayload(base64Candidate, req.TxBytesHex)
	if err != nil {
		audit.LogEvent("tx_haedal_execute_txbytes", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := executeManagedHaedalTxBytes(req.UID, txBytesBase64, nil, nil)
	if err != nil {
		audit.LogEvent("tx_haedal_execute_txbytes", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		if gateErr, ok := err.(*Share2GateError); ok {
			http.Error(w, gateErr.reason, gateErr.status)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.LogEvent("tx_haedal_execute_txbytes", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("from=%s", res.From))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// 方案1 逻辑主体 直接传txbytes 以及签名模式 由sandbox 进行处理
func executeManagedHaedalTxBytes(uid string, txBytesBase64 string, meta *signer.SignRequest, intent *policy.Intent) (*HaedalSuiTxResponse, error) {
	txBytesBase64 = strings.TrimSpace(txBytesBase64)
	if txBytesBase64 == "" {
		return nil, errors.New("txbytes is required")
	}

	if err := SuiDryRunTransactionBlock(txBytesBase64); err != nil {
		return nil, err
	}

	s, pe, snapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}
	from, err := utils.TransferFromAddress("sui", snapshot)
	if err != nil {
		return nil, err
	}
	if intent != nil {
		if strings.TrimSpace(intent.Chain) == "" {
			intent.Chain = "sui"
		}
		if err := validateIntentWithRefreshForEvent(pe, intent, snapshot, uid, "tx_sui_invoke"); err != nil {
			return nil, err
		}
	}
	builder := func(sponsorAddr string) (*BuildResult, error) {
		effectiveTxBytes := txBytesBase64
		if strings.TrimSpace(sponsorAddr) != "" {
			effectiveTxBytes, err = rebuildSuiSponsoredTxBytesFromRaw(context.Background(), txBytesBase64, from, sponsorAddr)
			if err != nil {
				return nil, err
			}
		}

		serializedSignature, err := signManagedSuiTransaction(s, effectiveTxBytes, &signer.SignRequest{
			UID:           uid,
			SignMode:      "swap",
			To:            intent.To,
			TokenContract: intent.TokenContract,
			AmountWei:     intent.AmountWei,
		})
		if err != nil {
			return nil, err
		}

		return &BuildResult{
			TxBase64:  effectiveTxBytes,
			Signature: serializedSignature,
		}, nil
	}

	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       "sui",
		FromAddress: from,
		UID:         uid,
	}, builder)

	if err != nil {
		return nil, err
	}
	if intent != nil {
		pe.Commit(intent)
	}

	return &HaedalSuiTxResponse{
		Chain:     "sui",
		From:      from,
		Action:    "haedal_execute_txbytes",
		Digest:    broadcastRes.SubmittedID,
		Sponsored: broadcastRes.Sponsored,
	}, nil
}

// 方案2 由用户主动介入 选择defi 进行具体的操作 （需要前置 询问用户具体的Defi 和操作选项）
func HandleSuiOptionedTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req HaedalOptionedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res := &HaedalSuiTxResponse{
		Chain:  "sui",
		Action: req.Option,
	}
	switch req.Defi {
	case "haedal":
		var err error
		res, err = executeManagedHaedalOptioned(&req)
		if err != nil {
			audit.LogEvent("tx_haedal_optioned", req.UID, RuntimeSandboxLabel, "failed", err.Error())
			if gateErr, ok := err.(*Share2GateError); ok {
				http.Error(w, gateErr.reason, gateErr.status)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "cetus":
		// TODO 后续增加cetus的选项
	default:
		http.Error(w, "unsupported defi option", http.StatusBadRequest)
		return
	}

	audit.LogEvent("tx_haedal_optioned", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("action=%s from=%s", res.Action, res.From))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// 方案2逻辑主体 针对Haedal的操作选项进行txbytes的获取 以及后续的签名和发送
func executeManagedHaedalOptioned(req *HaedalOptionedRequest) (*HaedalSuiTxResponse, error) {
	if req == nil {
		return nil, errors.New("missing request")
	}
	op := strings.TrimSpace(req.Option)
	if op == "" {
		return nil, errors.New("option is required")
	}
	apiPath, ok := haedalOptionsUrlList[op]
	if !ok {
		return nil, fmt.Errorf("unsupported option: %s", op)
	}

	s, _, snapshot, err := GetActiveSignerContext()
	if err != nil {
		return nil, err
	}
	from, err := utils.TransferFromAddress("sui", snapshot)
	if err != nil {
		return nil, err
	}

	body := req.Body
	if body == nil {
		body = map[string]any{}
	}
	// TODO:封控或者对haedal 操作进行阻断
	if strings.HasPrefix(apiPath, "api/v1/vehaedal/") {
		body["signerAddress"] = from
	} else {
		body["address"] = from
	}

	if strings.HasSuffix(apiPath, "/claim") {
		if _, ok := body["NFTObj"]; !ok && strings.Contains(apiPath, "/hasui/") {
			if v, err := haedalResolveFirstHasuiNFTObj(from); err == nil && v != "" {
				body["NFTObj"] = v
			}
		}
		if _, ok := body["NFTObj"]; !ok && strings.Contains(apiPath, "/hawal/") {
			if v, err := haedalResolveFirstHawalNFTObj(from); err == nil && v != "" {
				body["NFTObj"] = v
			}
		}
	}
	if strings.HasPrefix(apiPath, "api/v1/vehaedal/") &&
		(strings.Contains(apiPath, "add_to_existing_stake") || strings.Contains(apiPath, "extend_existing_lock") || strings.Contains(apiPath, "start_decay") || strings.Contains(apiPath, "stop_decay") || strings.Contains(apiPath, "unstake_and_claim")) {
		if _, ok := body["vehaedalObj"]; !ok {
			if v, err := haedalResolveFirstVehaedalObj(from); err == nil && v != "" {
				body["vehaedalObj"] = v
			}
		}
	}
	// 参数校验
	if err := validateHaedalOptionBody(apiPath, body); err != nil {
		return nil, err
	}
	// 通过haedal api 获取txbytes
	txBytesBase64, err := haedalFetchTxBytes(apiPath, body)
	if err != nil {
		return nil, err
	}
	// 进行签名
	builder := func(sponsorAddr string) (*BuildResult, error) {
		effectiveTxBytes := txBytesBase64
		if strings.TrimSpace(sponsorAddr) != "" {
			effectiveTxBytes, err = rebuildSuiSponsoredTxBytesFromRaw(context.Background(), txBytesBase64, from, sponsorAddr)
			if err != nil {
				return nil, err
			}
		}

		serializedSignature, err := signManagedSuiTransaction(s, effectiveTxBytes, &signer.SignRequest{
			UID:      strings.TrimSpace(req.UID),
			SignMode: "swap",

			// TODO: 下面3个字段可能不对
			To:            req.Body["to"].(string),
			TokenContract: req.Body["tokenContract"].(string),
			AmountWei:     req.Body["amount"].(string),
		})
		if err != nil {
			return nil, err
		}

		return &BuildResult{
			TxBase64:  effectiveTxBytes,
			Signature: serializedSignature,
		}, nil
	}

	broadcastRes, err := SubmitAndBroadcast(context.Background(), SponsorSubmitRequest{
		Chain:       "sui",
		FromAddress: from,
		UID:         req.UID,
	}, builder)
	if err != nil {
		return nil, err
	}

	return &HaedalSuiTxResponse{
		Chain:     "sui",
		From:      from,
		Action:    op,
		Digest:    broadcastRes.SubmittedID,
		Sponsored: broadcastRes.Sponsored,
	}, nil
}

// ========⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️⬇️================
// 内部函数
func SuiDryRunTransactionBlock(txBytesBase64 string) error {
	var out map[string]any
	if err := callChainRPC("sui", "sui_dryRunTransactionBlock", []interface{}{txBytesBase64}, &out); err != nil {
		return fmt.Errorf("sui dryrun failed: %w", err)
	}

	status := ""
	errMsg := ""
	if effects, ok := out["effects"].(map[string]any); ok {
		if st, ok := effects["status"].(map[string]any); ok {
			if v, ok := st["status"].(string); ok {
				status = v
			}
			if v, ok := st["error"].(string); ok {
				errMsg = v
			}
		}
	}

	s := strings.ToLower(strings.TrimSpace(status))
	if s != "" && s != "success" {
		errMsg = strings.TrimSpace(errMsg)
		if errMsg != "" {
			return fmt.Errorf("sui dryrun status %s: %s", s, errMsg)
		}
		return fmt.Errorf("sui dryrun status %s", s)
	}
	return nil
}

func rebuildSuiSponsoredTxBytesFromRaw(ctx context.Context, txBytesBase64, userAddrHex, sponsorAddrHex string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(txBytesBase64))
	if err != nil {
		return "", fmt.Errorf("invalid txbytes base64: %w", err)
	}

	var txData suitypes.TransactionData
	readLen, err := bcs.Unmarshal(raw, &txData)
	if err != nil {
		return "", fmt.Errorf("failed to parse sui transaction data: %w", err)
	}
	if readLen != len(raw) {
		return "", errors.New("invalid sui transaction data: trailing bytes found")
	}
	if txData.V1 == nil {
		return "", errors.New("invalid sui transaction data: missing v1")
	}
	if txData.V1.Kind.ProgrammableTransaction == nil {
		return "", errors.New("only programmable transaction is supported for sponsored execution")
	}

	rpcURL, err := chainRPCURL("sui")
	if err != nil {
		return "", err
	}
	client := suiclient.NewSuiClient(rpcURL)
	gasBudget := txData.V1.GasData.Budget
	if gasBudget == 0 {
		gasBudget = 8_000_000
	}
	return BuildSuiSponsoredTransactionFromKind(
		ctx,
		client,
		txData.V1.Kind,
		txData.V1.Expiration,
		userAddrHex,
		sponsorAddrHex,
		gasBudget,
	)
}

// Defi:haedal 相关逻辑
func haedalResolveFirstHasuiNFTObj(address string) (string, error) {
	var out haedalUnstakeTicketsListResponse
	if err := haedalPostJSON("api/v1/hasui/get_unstake_tickets_list", map[string]string{"address": address}, &out); err != nil {
		return "", err
	}
	if len(out.List) == 0 || strings.TrimSpace(out.List[0].ObjectId) == "" {
		return "", errors.New("no claimable unstake tickets found; nft_obj is required")
	}
	return strings.TrimSpace(out.List[0].ObjectId), nil
}

func haedalResolveFirstHawalNFTObj(address string) (string, error) {
	var out haedalUnstakeTicketsListResponse
	if err := haedalPostJSON("api/v1/hawal/get_unstake_tickets_list", map[string]string{"address": address}, &out); err != nil {
		return "", err
	}
	if len(out.List) == 0 || strings.TrimSpace(out.List[0].ObjectId) == "" {
		return "", errors.New("no claimable unstake tickets found; nft_obj is required")
	}
	return strings.TrimSpace(out.List[0].ObjectId), nil
}

func haedalResolveFirstVehaedalObj(address string) (string, error) {
	var out haedalVehaedalListResponse
	if err := haedalPostJSON("api/v1/vehaedal/get_vehaedal_list", map[string]string{"address": address}, &out); err != nil {
		return "", err
	}
	if len(out.List) == 0 || strings.TrimSpace(out.List[0].ObjectId) == "" {
		return "", errors.New("no vehaedal position found; vehaedal_obj is required")
	}
	return strings.TrimSpace(out.List[0].ObjectId), nil
}

func haedalFetchTxBytes(apiPath string, body any) (string, error) {
	var out haedalTxBytesResponse
	if err := haedalPostJSON(apiPath, body, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.TxBytes) == "" {
		return "", errors.New("haedal api returned empty txBytes")
	}
	return strings.TrimSpace(out.TxBytes), nil
}

func haedalPostJSON(apiPath string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}
	url := strings.TrimRight(haedalSkillUrl, "/") + "/" + strings.TrimLeft(apiPath, "/")

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("haedal api request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read haedal api response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr haedalAPIError
		_ = json.Unmarshal(data, &apiErr)
		msg := strings.TrimSpace(apiErr.Msg)
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		if msg == "" {
			msg = "haedal api error"
		}
		return fmt.Errorf("haedal api error (status %d): %s", resp.StatusCode, msg)
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to decode haedal api response: %w", err)
	}
	return nil
}

// 用来校验body 是否合法
func validateHaedalOptionBody(apiPath string, body map[string]any) error {
	reqStr := func(key string) bool {
		v, ok := body[key]
		if !ok {
			return false
		}
		s, ok := v.(string)
		return ok && strings.TrimSpace(s) != ""
	}
	reqArr := func(key string) bool {
		v, ok := body[key]
		if !ok {
			return false
		}
		_, ok = v.([]any)
		if ok {
			return true
		}
		_, ok = v.([]string)
		return ok
	}
	// 不同的操作选项 不同的参数要求
	switch {
	case strings.HasPrefix(apiPath, "api/v1/hasui/"):
		if strings.HasSuffix(apiPath, "/stake") {
			if !reqStr("amount") {
				return errors.New("amount is required")
			}
		} else if strings.HasSuffix(apiPath, "/withdraw") || strings.HasSuffix(apiPath, "/withdraw_instant") {
			if !reqStr("amount") {
				return errors.New("amount is required")
			}
		} else if strings.HasSuffix(apiPath, "/claim") {
			if !reqStr("NFTObj") {
				return errors.New("NFTObj is required")
			}
		}
	case strings.HasPrefix(apiPath, "api/v1/hawal/"):
		if strings.HasSuffix(apiPath, "/stake") {
			if !reqStr("amount") {
				return errors.New("amount is required")
			}
		} else if strings.HasSuffix(apiPath, "/withdraw") || strings.HasSuffix(apiPath, "/withdraw_instant") {
			if !reqStr("amount") {
				return errors.New("amount is required")
			}
		} else if strings.HasSuffix(apiPath, "/claim") {
			if !reqStr("NFTObj") {
				return errors.New("NFTObj is required")
			}
		}
	case strings.HasPrefix(apiPath, "api/v1/vehaedal/"):
		if strings.Contains(apiPath, "add_stake") {
			if !reqStr("amount") || !reqStr("lockWeeks") {
				return errors.New("amount and lockWeeks are required")
			}
		} else if strings.Contains(apiPath, "add_to_existing_stake") {
			if !reqStr("amount") || !reqStr("vehaedalObj") {
				return errors.New("amount and vehaedalObj are required")
			}
		} else if strings.Contains(apiPath, "extend_existing_lock") {
			if !reqStr("additionalWeeks") || !reqStr("vehaedalObj") {
				return errors.New("additionalWeeks and vehaedalObj are required")
			}
		} else if strings.Contains(apiPath, "start_decay") || strings.Contains(apiPath, "stop_decay") || strings.Contains(apiPath, "unstake_and_claim") {
			if !reqStr("vehaedalObj") {
				return errors.New("vehaedalObj is required")
			}
		} else if strings.Contains(apiPath, "claim_rewards_v2") && !strings.Contains(apiPath, "epoch_1") {
			if !reqArr("periods") {
				return errors.New("periods is required")
			}
		}
	}
	return nil
}

// Defi:cetus 相关逻辑
