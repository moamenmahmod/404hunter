# 404Hunter 🔍

**Advanced Subdomain Takeover Detection Tool**

404Hunter is a comprehensive subdomain takeover detection tool that combines the authoritative "Can I take over XYZ?" database with advanced technical validation to provide highly accurate, low false-positive subdomain takeover detection.

## 🚀 Features

### Core Capabilities
- **Authoritative Database Integration**: Uses the official "Can I take over XYZ?" fingerprints.json database
- **Weighted Scoring System**: 70% database authority + 30% technical validation
- **Comprehensive Analysis**: Multi-phase detection with detailed evidence tracking
- **False Positive Reduction**: Advanced filtering to minimize false alerts
- **Risk Assessment**: Business impact evaluation and remediation guidance

### Advanced Detection Methods
- **DNS Analysis**: NXDOMAIN detection and CNAME validation
- **HTTP/HTTPS Testing**: Multiple status code analysis and content inspection
- **Service-Specific API Validation**: GitHub, AWS S3, Azure, and more
- **Fingerprint Matching**: Content and title-based pattern detection
- **CDN Detection**: Identifies proxy/CDN interference

### Enhanced Output
- **Risk Levels**: CRITICAL, HIGH, MEDIUM, LOW, VERY_LOW
- **Takeover Difficulty**: Easy, Moderate, Hard assessments
- **Business Impact**: Contextual risk evaluation
- **Remediation Advice**: Specific fix recommendations

## 📦 Installation
### Install with Go (Recommended)
```bash
go install github.com/moamenmahmod/404hunter@latest
```
### Prerequisites
- Go 1.20 or higher

### Build from Source
```bash
git clone https://github.com/moamenmahmod/404hunter.git
cd 404hunter
go build -o 404hunter .
```

## 🔧 Usage

### Basic Scan
```bash
./404hunter scan -i subdomains.txt
```

### Advanced Options
```bash
./404hunter scan -i subdomains.txt -o results.json --timeout 15 --workers 100
```

### Command Line Options
- `-i, --input`: Path to subdomains file (required)
- `-o, --output`: Output JSON file (default: output.json)
- `--timeout`: HTTP timeout in seconds (default: 10)
- `--workers`: Number of concurrent workers (default: 50)
- `--no-banner`: Disable banner output

## 📊 Output Format

```json
{
  "subdomain": "test.example.com",
  "cname": "nonexistent.github.io",
  "service": "Github",
  "confidence": "95%",
  "risk_level": "CRITICAL",
  "takeover_difficulty": "Easy",
  "reasons": [
    "Service identified: Github → +20%",
    "Service status: Edge Case → +20%",
    "Fingerprint matched in content → +19%",
    "Found in takeover database (Easy difficulty) → +25%",
    "Easy takeover difficulty → +50%",
    "High success rate (85%) → +35%",
    "Community verified → +30%"
  ],
  "evidence_sources": {
    "can_i_takeover_xyz": {
      "matched": true,
      "confidence_contribution": 139
    },
    "technical_validation": {
      "matched": true,
      "confidence_contribution": 18
    },
    "dns_analysis": {
      "matched": false,
      "confidence_contribution": 0
    },
    "api_validation": {
      "matched": true,
      "confidence_contribution": 40,
      "details": "Repository existence validated"
    }
  },
  "false_positive_likelihood": "VERY_LOW",
  "business_impact": "HIGH",
  "remediation": "Remove CNAME record pointing to nonexistent.github.io or create legitimate Github resource",
  "verification_timestamp": "2024-01-15T10:30:00Z",
  "requires_manual_review": false
}
```

## 🎯 Confidence Scoring

### Weighted System (Total: 100%)
- **Can I Take Over XYZ Database (70%)**:
  - Service identification and fingerprint matching
  - Community-verified takeover difficulty
  - Historical success rates
  - Service vulnerability status

- **Technical Validation (30%)**:
  - DNS analysis (NXDOMAIN detection)
  - HTTP/HTTPS response analysis
  - Service-specific API validation
  - False positive reduction

### Risk Levels
- **CRITICAL (80-100%)**: High confidence, immediate action required
- **HIGH (60-79%)**: Likely takeover, investigate promptly
- **MEDIUM (40-59%)**: Possible takeover, manual review recommended
- **LOW (20-39%)**: Low probability, monitor
- **VERY_LOW (0-19%)**: Minimal risk

## 🛡️ Supported Services

404Hunter supports detection for 70+ services including:

- **Cloud Platforms**: AWS S3, Azure, Google Cloud
- **Hosting Services**: GitHub Pages, Netlify, Heroku
- **CDN Services**: CloudFront, Fastly
- **SaaS Platforms**: HubSpot, Zendesk, Intercom
- **And many more...

## 🔍 How It Works

1. **DNS Resolution**: Resolves CNAME records and checks for NXDOMAIN
2. **Service Identification**: Matches CNAMEs against known service patterns
3. **HTTP Analysis**: Tests HTTP/HTTPS responses and analyzes content
4. **Database Lookup**: Cross-references with "Can I take over XYZ?" data
5. **API Validation**: Performs service-specific existence checks
6. **Risk Assessment**: Calculates weighted confidence and business impact
7. **Report Generation**: Provides detailed findings with remediation advice

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any domains or systems.


---

**404Hunter** - Advanced Subdomain Takeover Detection 🔍
