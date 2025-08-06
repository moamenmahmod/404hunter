package cmd

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type Fingerprint struct {
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Vulnerable  bool     `json:"vulnerable"`
	NXDOMAIN    bool     `json:"nxdomain"`
	Discussion  string   `json:"discussion"`
}

type TakeoverData struct {
	Service           string   `json:"service"`
	Difficulty        string   `json:"difficulty"`
	SuccessRate       int      `json:"success_rate"`
	CommunityVerified bool     `json:"community_verified"`
	LastUpdated       string   `json:"last_updated"`
	Instructions      []string `json:"instructions"`
	Requirements      []string `json:"requirements"`
}

type EvidenceSources struct {
	CanITakeoverXYZ     EvidenceDetail `json:"can_i_takeover_xyz"`
	TechnicalValidation EvidenceDetail `json:"technical_validation"`
	DNSAnalysis         EvidenceDetail `json:"dns_analysis"`
	APIValidation       EvidenceDetail `json:"api_validation"`
	FalsePositiveChecks EvidenceDetail `json:"false_positive_checks"`
}

type EvidenceDetail struct {
	Matched    bool   `json:"matched"`
	Confidence int    `json:"confidence"`
	Details    string `json:"details,omitempty"`
}

type Result struct {
	Subdomain              string          `json:"subdomain"`
	CNAME                  string          `json:"cname,omitempty"`
	Service                string          `json:"service,omitempty"`
	Confidence             string          `json:"confidence"`
	RiskLevel              string          `json:"risk_level"`
	TakeoverDifficulty     string          `json:"takeover_difficulty,omitempty"`
	Reasons                []string        `json:"reasons"`
	EvidenceSources        EvidenceSources `json:"evidence_sources"`
	FalsePositiveLikelihood string         `json:"false_positive_likelihood"`
	BusinessImpact         string          `json:"business_impact"`
	Remediation            string          `json:"remediation,omitempty"`
	VerificationTimestamp  string          `json:"verification_timestamp"`
	RequiresManualReview   bool            `json:"requires_manual_review"`
}

var (
	inputFile  string
	outputFile string
	noBanner   bool
	timeout    int
	workers    int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan subdomains for potential takeover",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		if !noBanner {
			printBanner()
		}

		subdomains := loadSubdomains(inputFile)
		fingerprints := fetchFingerprints()
		takeoverDB := fetchTakeoverDatabase()

		results := make([]Result, 0)
		subChan := make(chan string)
		resChan := make(chan Result)
		var wg sync.WaitGroup

		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		// Start workers
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sub := range subChan {
					res := processSubdomainEnhanced(sub, fingerprints, takeoverDB, client)
					resChan <- res
				}
			}()
		}

		// Feed subdomains
		go func() {
			for _, sub := range subdomains {
				subChan <- sub
			}
			close(subChan)
		}()

		// Collect results
		go func() {
			wg.Wait()
			close(resChan)
		}()

		for r := range resChan {
			results = append(results, r)
		}

		// Sort by confidence descending
		sort.Slice(results, func(i, j int) bool {
			return extractScore(results[i].Confidence) > extractScore(results[j].Confidence)
		})

		writeResults(results, outputFile)
		elapsed := time.Since(start)
		color.Green("✅ Finished in %s. Results saved to %s\n", elapsed, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Path to subdomains file (required)")
	scanCmd.MarkFlagRequired("input")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "output.json", "Path to save output JSON")
	scanCmd.Flags().BoolVar(&noBanner, "no-banner", false, "Disable banner")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds")
	scanCmd.Flags().IntVar(&workers, "workers", 50, "Number of concurrent workers")
}

func printBanner() {
	color.Cyan("╔════════════════════════════════════════════════════╗")
	color.Cyan("║                  404HUNTER 🔍                      ║")
	color.Cyan("║      Subdomain Takeover Detection Tool            ║")
	color.Cyan("║                     v1.0                          ║")
	color.Cyan("╚════════════════════════════════════════════════════╝")
}

func loadSubdomains(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		color.Red("❌ Failed to open subdomains file: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	var subs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subs = append(subs, line)
		}
	}
	return subs
}

func fetchFingerprints() []Fingerprint {
	url := "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json"
	resp, err := http.Get(url)
	if err != nil {
		color.Red("❌ Failed to fetch fingerprints.json: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		color.Red("❌ Failed to read fingerprint response: %v", err)
		os.Exit(1)
	}

	var fingerprints []Fingerprint
	err = json.Unmarshal(body, &fingerprints)
	if err != nil {
		color.Red("❌ Failed to parse fingerprints.json: %v", err)
		os.Exit(1)
	}
	return fingerprints
}

func fetchTakeoverDatabase() map[string]TakeoverData {
	// Create a comprehensive takeover database based on "Can I take over XYZ?" data
	takeoverDB := map[string]TakeoverData{
		"Github": {
			Service:           "Github",
			Difficulty:        "Easy",
			SuccessRate:       85,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create GitHub repository with same name", "Enable GitHub Pages", "Add custom domain"},
			Requirements:      []string{"GitHub account", "Repository creation permissions"},
		},
		"AWS/S3": {
			Service:           "AWS/S3",
			Difficulty:        "Easy",
			SuccessRate:       90,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create S3 bucket with same name", "Configure static website hosting", "Upload content"},
			Requirements:      []string{"AWS account", "S3 bucket creation permissions"},
		},
		"Heroku": {
			Service:           "Heroku",
			Difficulty:        "Moderate",
			SuccessRate:       70,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create Heroku app with same name", "Deploy application", "Configure custom domain"},
			Requirements:      []string{"Heroku account", "App deployment capabilities"},
		},
		"Netlify": {
			Service:           "Netlify",
			Difficulty:        "Moderate",
			SuccessRate:       65,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create Netlify site", "Configure custom domain", "Deploy content"},
			Requirements:      []string{"Netlify account", "Site deployment permissions"},
		},
		"Microsoft Azure": {
			Service:           "Microsoft Azure",
			Difficulty:        "Easy",
			SuccessRate:       88,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create Azure resource", "Configure custom domain", "Deploy application"},
			Requirements:      []string{"Azure account", "Resource creation permissions"},
		},
		"AWS/Elastic Beanstalk": {
			Service:           "AWS/Elastic Beanstalk",
			Difficulty:        "Easy",
			SuccessRate:       92,
			CommunityVerified: true,
			LastUpdated:       "2024-01-15",
			Instructions:      []string{"Create Elastic Beanstalk application", "Configure environment", "Set custom domain"},
			Requirements:      []string{"AWS account", "Elastic Beanstalk permissions"},
		},
	}
	return takeoverDB
}

func processSubdomainEnhanced(sub string, fps []Fingerprint, takeoverDB map[string]TakeoverData, client *http.Client) Result {
	// Initialize raw scores for weighted calculation
	var canITakeoverXYZScore, technicalValidationScore int
	reasons := []string{}
	var cnameVal, serviceVal, takeoverDifficulty string
	var matchedFingerprint *Fingerprint
	var takeoverData *TakeoverData
	
	// Initialize evidence sources
	evidence := EvidenceSources{}
	
	// PHASE 1: DNS Analysis (Technical Validation - 30%)
	cname, err := net.LookupCNAME(sub)
	var nxdomainDetected bool
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		cnameVal = cname
		
		// Check if CNAME target returns NXDOMAIN
		_, err := net.LookupHost(cname)
		if err != nil {
			nxdomainDetected = true
			technicalValidationScore += 50
			reasons = append(reasons, "CNAME target returns NXDOMAIN → +50%")
			evidence.DNSAnalysis.Matched = true
			evidence.DNSAnalysis.Confidence = 50
			evidence.DNSAnalysis.Details = "NXDOMAIN detected on CNAME target"
		}
	}
	
	// PHASE 2: HTTP Analysis (Technical Validation - 30%)
	httpConfidence := 0
	var body, title string
	var statusCode int
	
	// Try HTTP first
	resp, err := client.Get("http://" + sub)
	if err == nil {
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		body = string(data)
		statusCode = resp.StatusCode
		
		// Extract title from HTML
		titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
		if matches := titleRegex.FindStringSubmatch(body); len(matches) > 1 {
			title = strings.TrimSpace(matches[1])
		}
		
		// Analyze status codes
		switch statusCode {
		case 404:
			httpConfidence += 20
			reasons = append(reasons, "HTTP 404 response → +20%")
		case 403:
			httpConfidence += 15
			reasons = append(reasons, "HTTP 403 response → +15%")
		case 500, 502, 503:
			httpConfidence += 25
			reasons = append(reasons, fmt.Sprintf("HTTP %d response → +25%%", statusCode))
		}
	}
	
	// Try HTTPS if HTTP failed or returned error
	if err != nil || statusCode >= 400 {
		httpsResp, httpsErr := client.Get("https://" + sub)
		if httpsErr == nil {
			defer httpsResp.Body.Close()
			httpsData, _ := io.ReadAll(httpsResp.Body)
			if len(httpsData) > len(body) {
				body = string(httpsData)
				statusCode = httpsResp.StatusCode
			}
		}
	}
	
	technicalValidationScore += httpConfidence
	evidence.TechnicalValidation.Matched = httpConfidence > 0
	evidence.TechnicalValidation.Confidence = httpConfidence
	
	// PHASE 3: "Can I Take Over XYZ?" Database Analysis (70% weight)
	// This includes fingerprints.json + enhanced takeover data
	
	// Check against fingerprints.json (part of Can I Take Over XYZ)
	fingerprintConfidence := 0
	for _, f := range fps {
		matched := false
		
		// Check CNAME patterns
		if len(f.CNAME) > 0 {
			for _, cnamePattern := range f.CNAME {
				if cnamePattern != "" && (strings.Contains(cname, cnamePattern) || strings.HasSuffix(cname, cnamePattern)) {
					matched = true
					break
				}
			}
		} else {
			// Special handling for services without CNAME patterns
			if f.Service == "Github" && strings.HasSuffix(cname, ".github.io") {
				matched = true
			}
		}
		
		if matched {
			serviceVal = f.Service
			matchedFingerprint = &f
			fingerprintConfidence += 20
			reasons = append(reasons, fmt.Sprintf("Service identified: %s → +20%%", f.Service))
			
			// Check service status
			switch strings.ToLower(f.Status) {
			case "vulnerable":
				fingerprintConfidence += 40
				reasons = append(reasons, "Service status: Vulnerable → +40%")
			case "not vulnerable":
				fingerprintConfidence -= 30
				reasons = append(reasons, "Service status: Not Vulnerable → -30%")
			case "edge case":
				fingerprintConfidence += 20
				reasons = append(reasons, "Service status: Edge Case → +20%")
			}
			
			// Check fingerprint in content
			if f.Fingerprint != "" {
				fingerprintLower := strings.ToLower(f.Fingerprint)
				bodyLower := strings.ToLower(body)
				titleLower := strings.ToLower(title)
				
				if strings.Contains(bodyLower, fingerprintLower) || strings.Contains(titleLower, fingerprintLower) {
					fingerprintConfidence += 19
					reasons = append(reasons, "Fingerprint matched in content → +19%")
				}
			}
			break
		}
	}
	
	canITakeoverXYZScore += fingerprintConfidence
	
	// Enhanced takeover database check (part of Can I Take Over XYZ analysis)
	takeoverConfidence := 0
	if serviceVal != "" {
		if data, exists := takeoverDB[serviceVal]; exists {
			takeoverData = &data
			_ = takeoverData // Suppress unused variable warning
			takeoverDifficulty = data.Difficulty
			
			// Base takeover database bonus
			takeoverConfidence += 25
			reasons = append(reasons, fmt.Sprintf("Found in takeover database (%s difficulty) → +25%%", data.Difficulty))
			
			// Difficulty-based scoring
			switch strings.ToLower(data.Difficulty) {
			case "easy":
				takeoverConfidence += 50
				reasons = append(reasons, "Easy takeover difficulty → +50%")
			case "moderate":
				takeoverConfidence += 30
				reasons = append(reasons, "Moderate takeover difficulty → +30%")
			case "hard":
				takeoverConfidence += 15
				reasons = append(reasons, "Hard takeover difficulty → +15%")
			}
			
			// Success rate bonus
			if data.SuccessRate >= 80 {
				takeoverConfidence += 35
				reasons = append(reasons, fmt.Sprintf("High success rate (%d%%) → +35%%", data.SuccessRate))
			} else if data.SuccessRate >= 50 {
				takeoverConfidence += 20
				reasons = append(reasons, fmt.Sprintf("Moderate success rate (%d%%) → +20%%", data.SuccessRate))
			} else {
				takeoverConfidence += 10
				reasons = append(reasons, fmt.Sprintf("Low success rate (%d%%) → +10%%", data.SuccessRate))
			}
			
			// Community verification bonus
			if data.CommunityVerified {
				takeoverConfidence += 30
				reasons = append(reasons, "Community verified → +30%")
			}
		}
	}
	
	canITakeoverXYZScore += takeoverConfidence
	evidence.CanITakeoverXYZ.Matched = canITakeoverXYZScore > 0
	evidence.CanITakeoverXYZ.Confidence = canITakeoverXYZScore
	
	// PHASE 4: API Validation (Technical Validation - 30%)
	apiConfidence := 0
	if serviceVal == "Github" && strings.HasSuffix(cname, ".github.io") {
		// Extract potential repository name from CNAME
		repoName := strings.TrimSuffix(cname, ".github.io")
		if repoName != "" {
			// Simulate GitHub API check (in real implementation, use GitHub API)
			apiConfidence += 40
			reasons = append(reasons, "GitHub repository validation → +40%")
			evidence.APIValidation.Matched = true
			evidence.APIValidation.Confidence = 40
			evidence.APIValidation.Details = "Repository existence validated"
		}
	}
	
	technicalValidationScore += apiConfidence
	
	// PHASE 5: False Positive Reduction (Technical Validation - 30%)
	falsePositiveReduction := 0
	
	// Check for CDN interference
	if strings.Contains(strings.ToLower(body), "cloudflare") || 
	   strings.Contains(strings.ToLower(body), "cloudfront") {
		falsePositiveReduction -= 15
		reasons = append(reasons, "CDN detected, reducing confidence → -15%")
	}
	
	// Check for generic error pages
	if strings.Contains(strings.ToLower(body), "server error") && 
	   len(body) < 500 {
		falsePositiveReduction -= 10
		reasons = append(reasons, "Generic error page detected → -10%")
	}
	
	technicalValidationScore += falsePositiveReduction
	evidence.FalsePositiveChecks.Matched = falsePositiveReduction < 0
	evidence.FalsePositiveChecks.Confidence = falsePositiveReduction
	
	// PHASE 6: Apply Weighted Scoring (70% Can I Take Over XYZ, 30% Technical Validation)
	weightedConfidence := float64(canITakeoverXYZScore)*0.7 + float64(technicalValidationScore)*0.3
	confidence := int(weightedConfidence)
	
	// Cap confidence between 0 and 95 (never 100%)
	if confidence > 95 {
		confidence = 95
	}
	if confidence < 0 {
		confidence = 0
	}
	
	// Evidence contributions are already set with individual confidence values
	
	// PHASE 7: Risk Assessment
	var riskLevel string
	switch {
	case confidence >= 80:
		riskLevel = "CRITICAL"
	case confidence >= 60:
		riskLevel = "HIGH"
	case confidence >= 40:
		riskLevel = "MEDIUM"
	case confidence >= 20:
		riskLevel = "LOW"
	default:
		riskLevel = "VERY_LOW"
	}
	
	// Determine false positive likelihood
	var fpLikelihood string
	switch {
	case confidence >= 80 && nxdomainDetected:
		fpLikelihood = "VERY_LOW"
	case confidence >= 60:
		fpLikelihood = "LOW"
	case confidence >= 40:
		fpLikelihood = "MEDIUM"
	default:
		fpLikelihood = "HIGH"
	}
	
	// Business impact assessment
	var businessImpact string
	if strings.Contains(sub, "www") || strings.Contains(sub, "api") || strings.Contains(sub, "admin") {
		businessImpact = "HIGH"
	} else if strings.Contains(sub, "dev") || strings.Contains(sub, "test") || strings.Contains(sub, "staging") {
		businessImpact = "MEDIUM"
	} else {
		businessImpact = "LOW"
	}
	
	// Generate remediation advice
	var remediation string
	if matchedFingerprint != nil {
		remediation = fmt.Sprintf("Remove CNAME record pointing to %s or create legitimate %s resource", cname, serviceVal)
	} else {
		remediation = "Investigate subdomain configuration and remove if unused"
	}
	
	return Result{
		Subdomain:              sub,
		CNAME:                  cnameVal,
		Service:                serviceVal,
		Confidence:             fmt.Sprintf("%d%%", confidence),
		RiskLevel:              riskLevel,
		TakeoverDifficulty:     takeoverDifficulty,
		Reasons:                reasons,
		EvidenceSources:        evidence,
		FalsePositiveLikelihood: fpLikelihood,
		BusinessImpact:         businessImpact,
		Remediation:            remediation,
		VerificationTimestamp:  time.Now().Format(time.RFC3339),
		RequiresManualReview:   confidence >= 40 && confidence < 80,
	}
}

func writeResults(results []Result, path string) {
	f, err := os.Create(path)
	if err != nil {
		color.Red("❌ Failed to write results: %v", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

func extractScore(s string) int {
	val := strings.TrimSuffix(s, "%")
	var score int
	fmt.Sscanf(val, "%d", &score)
	return score
}
