package others

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sandbox/internals/utils"
)

const (
	safuSkillBaseURL       = "https://safuskill.ai"
	safuSkillTopPageSize   = 20
	safuSkillHTTPTimeout   = 30 * time.Second
	safuSkillCategoryTop20 = "BNBChain Skills"
	safuSkillInitStateFile = ".safuskill_preloaded.json"
)

type safuSkillListResponse struct {
	Skills []safuSkillSummary `json:"skills"`
}

type safuSkillSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SourceRepo string `json:"sourceRepo"`
	SourcePath string `json:"sourcePath"`
	ScanResult struct {
		Status string `json:"status"`
	} `json:"scanResult"`
}

type safuSkillDetail struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SourceRepo string `json:"sourceRepo"`
	SourcePath string `json:"sourcePath"`
	ScanResult struct {
		Status      string `json:"status"`
		RiskLevel   string `json:"riskLevel"`
		SafeToUse   bool   `json:"safeToUse"`
		ScanSummary string `json:"scanSummary"`
		ScanDetails struct {
			URL string `json:"url"`
		} `json:"scanDetails"`
	} `json:"scanResult"`
}

type sandboxSkillMetadata struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	SourceRepo  string    `json:"source_repo,omitempty"`
	SourcePath  string    `json:"source_path,omitempty"`
	DownloadURL string    `json:"download_url"`
	RiskLevel   string    `json:"risk_level,omitempty"`
	SafeToUse   bool      `json:"safe_to_use"`
	SavedAt     time.Time `json:"saved_at"`
}

func TriggerStartupSafuSkillPreload() {
	go func() {
		if _, err := preloadTopSafuSkills(false); err != nil {
			log.Printf("[claw wallet sandbox] SafuSkill preload failed: %v", err)
		}
	}()
}

func HandlePreloadSafuSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := preloadTopSafuSkills(true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"preloaded_count": len(items),
		"skills":          items,
	})
}

func HandleResolveSafuSkillByName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	localPath, exists, err := localSkillPathIfExists(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	detail, err := searchSafuSkillByName(name)
	if err != nil {
		if exists {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":        "ok",
				"source":        "local_cache_stale",
				"name":          name,
				"installed":     true,
				"local_path":    localPath,
				"reload_needed": true,
				"update_error":  err.Error(),
			})
			return
		}
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	localPath, metaPath, err := cacheSafuSkill(detail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"source":        "safuskill",
		"name":          detail.Name,
		"id":            detail.ID,
		"installed":     true,
		"local_path":    localPath,
		"metadata_path": metaPath,
		"reload_needed": true,
	})
}

func HandleReadSafuSkillContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	localPath, exists, err := localSkillPathIfExists(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, fmt.Sprintf("skill %q is not installed locally; call /api/v1/skills/by-name first", name), http.StatusNotFound)
		return
	}

	content, err := os.ReadFile(localPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"name":       name,
		"local_path": localPath,
		"content":    string(content),
	})
}

func preloadTopSafuSkills(force bool) ([]map[string]any, error) {
	if !force {
		done, err := hasCompletedSafuSkillPreload()
		if err != nil {
			return nil, err
		}
		if done {
			return []map[string]any{
				{"status": "already_initialized"},
			}, nil
		}
	}

	list, err := fetchSafuSkillList(safuSkillTopPageSize, safuSkillCategoryTop20, "")
	if err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(list))
	for _, item := range list {
		localPath, exists, err := localSkillPathIfExists(item.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			results = append(results, map[string]any{
				"id":         item.ID,
				"name":       item.Name,
				"status":     "cached",
				"local_path": localPath,
			})
			continue
		}

		detail, err := fetchSafuSkillDetail(item.ID)
		if err != nil {
			log.Printf("[claw wallet sandbox] SafuSkill detail fetch failed for %s (%s): %v", item.Name, item.ID, err)
			continue
		}
		localPath, _, err = cacheSafuSkill(detail)
		if err != nil {
			log.Printf("[claw wallet sandbox] SafuSkill cache failed for %s (%s): %v", item.Name, item.ID, err)
			continue
		}
		results = append(results, map[string]any{
			"id":         detail.ID,
			"name":       detail.Name,
			"status":     "downloaded",
			"local_path": localPath,
		})
	}

	if !force {
		if err := markSafuSkillPreloadComplete(len(results)); err != nil {
			return nil, err
		}
	}

	return results, nil
}

func searchSafuSkillByName(name string) (*safuSkillDetail, error) {
	list, err := fetchSafuSkillList(safuSkillTopPageSize, "", name)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("skill %q not found on SafuSkill", name)
	}

	chosen := list[0]
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item.Name), strings.TrimSpace(name)) {
			chosen = item
			break
		}
	}

	return fetchSafuSkillDetail(chosen.ID)
}

func fetchSafuSkillList(limit int, category, search string) ([]safuSkillSummary, error) {
	query := url.Values{}
	query.Set("page", "1")
	query.Set("limit", fmt.Sprintf("%d", limit))
	query.Set("sortBy", "downloads")
	if strings.TrimSpace(category) != "" {
		query.Set("category", category)
	}
	if strings.TrimSpace(search) != "" {
		query.Set("search", search)
	}

	var payload safuSkillListResponse
	if err := fetchJSON(safuSkillBaseURL+"/api/skills?"+query.Encode(), &payload); err != nil {
		return nil, err
	}
	return payload.Skills, nil
}

func fetchSafuSkillDetail(id string) (*safuSkillDetail, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("missing skill id")
	}
	var payload safuSkillDetail
	if err := fetchJSON(safuSkillBaseURL+"/api/skills/"+url.PathEscape(id), &payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.ScanResult.ScanDetails.URL) == "" {
		return nil, fmt.Errorf("skill %s does not expose scanResult.scanDetails.url", id)
	}
	return &payload, nil
}

func cacheSafuSkill(detail *safuSkillDetail) (string, string, error) {
	if detail == nil {
		return "", "", errors.New("missing skill detail")
	}
	downloadURL := strings.TrimSpace(detail.ScanResult.ScanDetails.URL)
	if downloadURL == "" {
		return "", "", fmt.Errorf("skill %s missing download url", detail.ID)
	}

	body, err := fetchBytes(downloadURL)
	if err != nil {
		return "", "", err
	}

	skillDir, err := sandboxSkillDir(detail.Name)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		return "", "", err
	}

	skillPath := filepath.Join(skillDir, "SKILL.md")
	if err := utils.AtomicWrite(skillPath, body); err != nil {
		return "", "", err
	}

	meta := sandboxSkillMetadata{
		ID:          detail.ID,
		Name:        detail.Name,
		SourceRepo:  detail.SourceRepo,
		SourcePath:  detail.SourcePath,
		DownloadURL: downloadURL,
		RiskLevel:   detail.ScanResult.RiskLevel,
		SafeToUse:   detail.ScanResult.SafeToUse,
		SavedAt:     time.Now().UTC(),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", "", err
	}
	metaPath := filepath.Join(skillDir, "metadata.json")
	if err := utils.AtomicWrite(metaPath, metaBytes); err != nil {
		return "", "", err
	}

	return skillPath, metaPath, nil
}

func localSkillPathIfExists(name string) (string, bool, error) {
	skillDir, err := sandboxSkillDir(name)
	if err != nil {
		return "", false, err
	}
	skillPath := filepath.Join(skillDir, "SKILL.md")
	info, err := os.Stat(skillPath)
	if err == nil && !info.IsDir() {
		return skillPath, true, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	return skillPath, false, nil
}

func sandboxSkillDir(name string) (string, error) {
	root, err := sandboxSkillRootDir()
	if err != nil {
		return "", err
	}
	dirName := sanitizeSkillDirName(name)
	if dirName == "" {
		return "", errors.New("invalid skill name")
	}
	return filepath.Join(root, dirName), nil
}

func sandboxSkillRootDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(exePath), "sandbox_skill"), nil
}

func sanitizeSkillDirName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

func fetchJSON(requestURL string, out any) error {
	resp, err := sandboxMarketplaceHTTPClient().Get(requestURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("request %s failed with HTTP %d: %s", requestURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}

func fetchBytes(requestURL string) ([]byte, error) {
	resp, err := sandboxMarketplaceHTTPClient().Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("download %s failed with HTTP %d: %s", requestURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

func sandboxMarketplaceHTTPClient() *http.Client {
	return &http.Client{Timeout: safuSkillHTTPTimeout}
}

func hasCompletedSafuSkillPreload() (bool, error) {
	statePath, err := safuSkillInitStatePath()
	if err != nil {
		return false, err
	}
	info, err := os.Stat(statePath)
	if err == nil && !info.IsDir() {
		return true, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

func markSafuSkillPreloadComplete(downloadedCount int) error {
	root, err := sandboxSkillRootDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	statePath, err := safuSkillInitStatePath()
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(map[string]any{
		"initialized":      true,
		"downloaded_count": downloadedCount,
		"updated_at":       time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return utils.AtomicWrite(statePath, payload)
}

func safuSkillInitStatePath() (string, error) {
	root, err := sandboxSkillRootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, safuSkillInitStateFile), nil
}
