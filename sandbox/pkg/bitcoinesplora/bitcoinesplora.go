package bitcoinesplora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var basesForTest []string

func SetBasesForTest(bases []string) {
	if len(bases) == 0 {
		basesForTest = nil
		return
	}
	basesForTest = append([]string(nil), bases...)
}

func Bases() []string {
	if len(basesForTest) > 0 {
		return append([]string(nil), basesForTest...)
	}
	return []string{"https://blockstream.info/api"}
}

func FetchGET(client *http.Client, path string, out interface{}) error {
	var lastErr error
	for _, base := range Bases() {
		url := strings.TrimRight(strings.TrimSpace(base), "/") + path
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("esplora get %s failed: %s", path, resp.Status)
			continue
		}
		if err := json.Unmarshal(body, out); err != nil {
			return err
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no esplora base configured")
}

func PickRecommendedFeeSatsPerVB(client *http.Client) (int64, error) {
	type feeResp struct {
		FastestFee int64 `json:"fastestFee"`
		HalfHour   int64 `json:"halfHourFee"`
		HourFee    int64 `json:"hourFee"`
		MinimumFee int64 `json:"minimumFee"`
	}
	var out feeResp
	if err := FetchGET(client, "/fee-estimates", &out); err == nil {
		switch {
		case out.HalfHour > 0:
			return out.HalfHour, nil
		case out.FastestFee > 0:
			return out.FastestFee, nil
		case out.HourFee > 0:
			return out.HourFee, nil
		case out.MinimumFee > 0:
			return out.MinimumFee, nil
		}
	}
	return 2, nil
}

func PostText(client *http.Client, path, contentType, body string) ([]byte, error) {
	var lastErr error
	for _, base := range Bases() {
		url := strings.TrimRight(strings.TrimSpace(base), "/") + path
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("esplora post %s failed: %s", path, resp.Status)
			continue
		}
		return data, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no esplora base configured")
}
