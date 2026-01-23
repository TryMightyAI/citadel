package patterns

// =============================================================================
// PATTERN DEFINITIONS BY CATEGORY
// All patterns are registered here and compiled once at package init.
// This provides a single source of truth for all security patterns.
// =============================================================================

// --- CREDENTIAL DETECTION PATTERNS (POST-HOOK) ---
func (r *Registry) registerCredentialPatterns() {
	cat := CategoryCredential

	// AWS
	r.register("aws_access_key", `(?i)AKIA[0-9A-Z]{16}`, cat, 85, "AWS Access Key ID")
	r.register("aws_secret", `(?i)aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}`, cat, 90, "AWS Secret Access Key")

	// Google Cloud
	r.register("gcp_api_key", `(?i)AIza[0-9A-Za-z\-_]{35}`, cat, 85, "Google API Key")
	r.register("gcp_service_account", `(?i)"type":\s*"service_account"`, cat, 80, "GCP Service Account JSON")

	// Azure (require credential context to avoid matching all UUIDs)
	r.register("azure_client_id", `(?i)(client[_\-]?id|tenant[_\-]?id|subscription[_\-]?id|app[_\-]?id)\s*[=:]\s*['"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, cat, 70, "Azure ID in context")

	// GitHub
	r.register("github_pat", `(?i)ghp_[0-9a-zA-Z]{36}`, cat, 85, "GitHub Personal Access Token")
	r.register("github_oauth", `(?i)gho_[0-9a-zA-Z]{36}`, cat, 85, "GitHub OAuth Token")
	r.register("github_app", `(?i)ghs_[0-9a-zA-Z]{36}`, cat, 85, "GitHub App Token")
	r.register("github_refresh", `(?i)ghr_[0-9a-zA-Z]{36}`, cat, 85, "GitHub Refresh Token")

	// Slack
	r.register("slack_bot_token", `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`, cat, 85, "Slack Bot Token")
	r.register("slack_user_token", `xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`, cat, 85, "Slack User Token")
	r.register("slack_app_token", `xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}`, cat, 85, "Slack App Token")
	r.register("slack_webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`, cat, 80, "Slack Webhook URL")

	// Twilio
	r.register("twilio_account_sid", `AC[a-f0-9]{32}`, cat, 75, "Twilio Account SID")
	r.register("twilio_auth_token", `(?i)(twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?[a-f0-9]{32}`, cat, 85, "Twilio Auth Token")

	// SendGrid
	r.register("sendgrid_api_key", `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, cat, 85, "SendGrid API Key")

	// Mailchimp
	r.register("mailchimp_api_key", `[a-f0-9]{32}-us[0-9]{1,2}`, cat, 75, "Mailchimp API Key")

	// Stripe
	r.register("stripe_secret", `(?i)sk_live_[0-9a-zA-Z]{24}`, cat, 90, "Stripe Secret Key")
	r.register("stripe_restricted", `(?i)rk_live_[0-9a-zA-Z]{24}`, cat, 85, "Stripe Restricted Key")

	// JWT
	r.register("jwt_token", `(?i)eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, cat, 75, "JWT Token")

	// OAuth and Client Secrets
	r.register("oauth_client_secret", `(?i)(client[_-]?secret|oauth[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`, cat, 85, "OAuth Client Secret")
	r.register("oauth_refresh_token", `(?i)refresh[_-]?token\s*[=:]\s*['"]?[A-Za-z0-9_\-\.]{20,}`, cat, 80, "OAuth Refresh Token")
	r.register("oauth_access_token", `(?i)access[_-]?token\s*[=:]\s*['"]?[A-Za-z0-9_\-\.]{20,}`, cat, 80, "OAuth Access Token")

	// Anthropic/AI API Keys
	r.register("anthropic_api_key", `sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}`, cat, 90, "Anthropic API Key")
	r.register("openai_api_key", `sk-[A-Za-z0-9]{20,}`, cat, 90, "OpenAI API Key")
	r.register("openai_proj_key", `sk-proj-[A-Za-z0-9_\-]{20,}`, cat, 90, "OpenAI Project API Key")
	r.register("cohere_api_key", `(?i)(cohere[_-]?api[_-]?key)\s*[=:]\s*['"]?[A-Za-z0-9]{40}`, cat, 85, "Cohere API Key")
	r.register("huggingface_token", `hf_[A-Za-z0-9]{20,}`, cat, 80, "HuggingFace Token")

	// Discord
	r.register("discord_token", `[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`, cat, 85, "Discord Bot Token")
	r.register("discord_webhook", `https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`, cat, 80, "Discord Webhook URL")

	// Telegram
	r.register("telegram_bot_token", `[0-9]{9,10}:[A-Za-z0-9_-]{35}`, cat, 80, "Telegram Bot Token")

	// Generic patterns
	r.register("api_key_assign", `(?i)api[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`, cat, 70, "API Key assignment")
	r.register("secret_key_assign", `(?i)secret[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`, cat, 75, "Secret Key assignment")
	r.register("password_assign", `(?i)password\s*[=:]\s*['"]?[^\s'"]{8,}`, cat, 70, "Password assignment")
	r.register("password_json", `(?i)"password"\s*:\s*"[^"]{8,}"`, cat, 75, "Password in JSON")
	r.register("bearer_token", `(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}`, cat, 75, "Bearer token")
	r.register("auth_header", `(?i)authorization:\s*bearer\s+[A-Za-z0-9_\-\.]+`, cat, 75, "Authorization header")
	r.register("basic_auth", `(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+`, cat, 80, "Basic Auth header")

	// Database connection strings
	r.register("mongodb_uri", `(?i)mongodb(\+srv)?://[^:]+:[^@]+@`, cat, 85, "MongoDB URI with credentials")
	r.register("postgres_uri", `(?i)postgres://[^:]+:[^@]+@`, cat, 85, "PostgreSQL URI with credentials")
	r.register("mysql_uri", `(?i)mysql://[^:]+:[^@]+@`, cat, 85, "MySQL URI with credentials")
	r.register("redis_uri", `(?i)redis://:[^@]+@`, cat, 85, "Redis URI with password")

	// Private keys
	r.register("private_key_header", `(?i)-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----`, cat, 95, "Private key header")
	r.register("pgp_private_key", `(?i)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`, cat, 95, "PGP private key")
}

// --- PATH TRAVERSAL PATTERNS (POST-HOOK) ---
func (r *Registry) registerPathTraversalPatterns() {
	cat := CategoryPathTraversal

	// Classic directory traversal
	r.register("path_traversal_unix", `(?i)\.\.\/\.\.\/`, cat, 65, "Unix path traversal (../)")
	r.register("path_traversal_win", `(?i)\.\.\\\.\.\\`, cat, 65, "Windows path traversal (..\\)")
	r.register("path_traversal_url", `(?i)%2e%2e[%2f%5c]`, cat, 70, "URL-encoded path traversal")
	r.register("path_overlong_utf8_1", `(?i)\.\.%c0%af`, cat, 75, "Overlong UTF-8 path traversal")
	r.register("path_overlong_utf8_2", `(?i)\.\.%c1%9c`, cat, 75, "Overlong UTF-8 path traversal")

	// Linux sensitive files
	r.register("linux_sensitive", `(?i)/etc/(passwd|shadow|hosts|sudoers)`, cat, 70, "Linux sensitive file access")
	r.register("ssh_keys", `(?i)/root/\.ssh`, cat, 75, "SSH key access")
	r.register("log_files", `(?i)/var/log/`, cat, 50, "Log file access")

	// Windows sensitive paths
	r.register("windows_system32", `(?i)C:\\Windows\\System32`, cat, 65, "Windows System32 access")
	r.register("windows_appdata", `(?i)C:\\Users\\.*\\AppData`, cat, 60, "Windows AppData access")

	// Special filesystem access
	r.register("file_protocol", `(?i)file:///`, cat, 70, "File protocol access")
	r.register("proc_self", `(?i)/proc/self/`, cat, 75, "Linux proc filesystem access")
	r.register("dev_network", `(?i)/dev/(tcp|udp)/`, cat, 80, "Device file for networking")
}

// --- NETWORK RECONNAISSANCE PATTERNS (POST-HOOK) ---
func (r *Registry) registerNetworkReconPatterns() {
	cat := CategoryNetworkRecon

	// Port scanning
	r.register("nmap", `(?i)nmap\s+(-[sSUATWMV]+\s+)*[\d\.\-/]+`, cat, 55, "Nmap port scan")
	r.register("masscan", `(?i)masscan\s+`, cat, 55, "Masscan port scan")
	r.register("netcat_full", `(?i)netcat\s+(-[a-z]+\s+)*[\d\.]+\s+\d+`, cat, 60, "Netcat connection")
	r.register("nc_short", `(?i)nc\s+(-[a-z]+\s+)*[\d\.]+\s+\d+`, cat, 60, "Netcat (nc) connection")

	// DNS enumeration
	r.register("dig_axfr", `(?i)dig\s+(axfr|any)\s+`, cat, 65, "DNS zone transfer")
	r.register("host_enum", `(?i)host\s+-[tl]\s+`, cat, 50, "Host enumeration")
	r.register("dnsenum", `(?i)dnsenum\s+`, cat, 55, "DNS enumeration tool")
	r.register("dnsrecon", `(?i)dnsrecon\s+`, cat, 55, "DNS reconnaissance tool")

	// Network discovery
	r.register("arp_scan", `(?i)arp\s+-[an]`, cat, 50, "ARP scanning")
	r.register("arping", `(?i)arping\s+`, cat, 45, "ARP ping")
	r.register("ping_sweep", `(?i)ping\s+-[cif]\s*\d+\s+[\d\.]+`, cat, 40, "ICMP sweep")
	r.register("fping", `(?i)fping\s+`, cat, 45, "Fast ping")

	// Service enumeration
	r.register("http_options", `(?i)curl\s+(-[XIH]+\s+)*.*OPTIONS`, cat, 50, "HTTP OPTIONS probe")
	r.register("nikto", `(?i)nikto\s+`, cat, 60, "Web vulnerability scanner")
	r.register("dirb", `(?i)dirb\s+`, cat, 55, "Directory bruteforce")
	r.register("gobuster", `(?i)gobuster\s+`, cat, 55, "Go directory buster")
	r.register("ffuf", `(?i)ffuf\s+`, cat, 55, "Fast web fuzzer")

	// Network info gathering
	r.register("ifconfig", `(?i)ifconfig\s*(-a)?`, cat, 35, "Network interfaces")
	r.register("ip_command", `(?i)ip\s+(addr|route|neigh)`, cat, 35, "IP command")
	r.register("netstat", `(?i)netstat\s+(-[antup]+)`, cat, 40, "Network statistics")
	r.register("ss_command", `(?i)ss\s+(-[antup]+)`, cat, 40, "Socket statistics")
	r.register("route_table", `(?i)route\s+(-n)?`, cat, 35, "Routing table")

	// Credential gathering over network
	r.register("responder", `(?i)responder\s+`, cat, 70, "LLMNR/NBT-NS poisoning")
	r.register("mimikatz", `(?i)mimikatz`, cat, 85, "Credential extraction")
	r.register("impacket", `(?i)impacket`, cat, 65, "Network protocol tools")
}

// --- PRIVILEGE ESCALATION PATTERNS (POST-HOOK) ---
func (r *Registry) registerPrivilegeEscPatterns() {
	cat := CategoryPrivilegeEsc

	// Sudo abuse
	r.register("sudo_list", `(?i)sudo\s+-l`, cat, 55, "List sudo privileges")
	r.register("sudo_su", `(?i)sudo\s+su`, cat, 75, "Switch to root via sudo")
	r.register("sudo_interactive", `(?i)sudo\s+-i`, cat, 75, "Interactive root shell")
	r.register("sudo_bash", `(?i)sudo\s+bash`, cat, 75, "Root bash via sudo")
	r.register("sudo_sh", `(?i)sudo\s+sh`, cat, 75, "Root shell via sudo")
	r.register("sudo_password_pipe", `(?i)echo\s+.*\|\s*sudo\s+-S`, cat, 80, "Password piping to sudo")

	// SUID/SGID manipulation
	r.register("chmod_suid", `(?i)chmod\s+[0-7]*[4-7][0-7]{2}\s+`, cat, 70, "SUID/SGID bit setting")
	r.register("chmod_add_suid", `(?i)chmod\s+[ugo]*\+s`, cat, 75, "Add SUID/SGID permission")
	r.register("find_suid", `(?i)find\s+.*-perm\s+-[46]000`, cat, 55, "Find SUID/SGID files")
	r.register("find_suid_alt", `(?i)find\s+.*-perm\s+/[46]000`, cat, 55, "Find SUID/SGID files (alt)")

	// Capability abuse
	r.register("getcap", `(?i)getcap\s+`, cat, 50, "List capabilities")
	r.register("setcap", `(?i)setcap\s+`, cat, 65, "Set capabilities")
	r.register("cap_setuid", `(?i)cap_setuid`, cat, 70, "setuid capability")

	// Container escape
	r.register("docker_privileged", `(?i)docker\s+run\s+.*--privileged`, cat, 80, "Privileged container")
	r.register("docker_root_mount", `(?i)docker\s+run\s+.*-v\s+/:/`, cat, 85, "Mount root filesystem")
	r.register("nsenter", `(?i)nsenter\s+`, cat, 70, "Enter namespace")

	// Kernel exploits
	r.register("dirtycow", `(?i)dirtycow`, cat, 90, "Dirty COW exploit")
	r.register("dirtypipe", `(?i)dirty_pipe`, cat, 90, "Dirty Pipe exploit")
	r.register("overlayfs_exploit", `(?i)overlayfs`, cat, 60, "OverlayFS exploits")

	// Cron abuse
	r.register("crontab_edit", `(?i)crontab\s+-[el]`, cat, 60, "Edit crontab")
	r.register("cron_directories", `(?i)/etc/cron\.(d|daily|hourly|weekly|monthly)`, cat, 55, "Cron directories")
	r.register("at_command", `(?i)at\s+.*</`, cat, 55, "at command with input")

	// Service manipulation
	r.register("systemctl_enable", `(?i)systemctl\s+(enable|start)`, cat, 50, "Enable/start services")
	r.register("service_start", `(?i)service\s+.*start`, cat, 45, "Start service")

	// Password/shadow manipulation
	r.register("passwd_cmd", `(?i)passwd\s+`, cat, 55, "Change password")
	r.register("add_shell_user", `(?i)/etc/passwd.*:/bin/(ba)?sh`, cat, 75, "Add shell user")
	r.register("useradd_special", `(?i)useradd\s+.*-[ogu]`, cat, 70, "Add user with special options")
	r.register("usermod_sudo", `(?i)usermod\s+.*-aG\s+(sudo|wheel|admin)`, cat, 80, "Add to privileged group")

	// GTFOBins patterns
	r.register("python_os_exec", `(?i)python[23]?\s+.*-c\s+.*import\s+os`, cat, 65, "Python command exec")
	r.register("perl_exec", `(?i)perl\s+.*-e\s+.*exec`, cat, 65, "Perl exec")
	r.register("ruby_exec", `(?i)ruby\s+.*-e\s+.*exec`, cat, 65, "Ruby exec")
	r.register("vim_shell_escape", `(?i)vim\s+.*-c\s+.*!`, cat, 70, "Vim shell escape")
	r.register("less_shell", `(?i)less\s+.*!/bin/(ba)?sh`, cat, 70, "Less shell escape")
	r.register("awk_system", `(?i)awk\s+.*system\s*\(`, cat, 65, "AWK system call")
}

// --- DESERIALIZATION ATTACK PATTERNS (POST-HOOK) ---
func (r *Registry) registerDeserializationPatterns() {
	cat := CategoryDeserialization

	// Python
	r.register("pickle_load", `(?i)pickle\.loads?\s*\(`, cat, 80, "Python pickle deserialization")
	r.register("cpickle_load", `(?i)cPickle\.loads?\s*\(`, cat, 80, "Python cPickle")
	r.register("marshal_load", `(?i)marshal\.loads?\s*\(`, cat, 75, "Python marshal")
	r.register("shelve_open", `(?i)shelve\.open\s*\(`, cat, 70, "Python shelve")
	r.register("yaml_unsafe_none", `(?i)yaml\.load\s*\([^)]*Loader\s*=\s*None`, cat, 75, "Unsafe YAML load")
	r.register("yaml_unsafe_load", `(?i)yaml\.unsafe_load\s*\(`, cat, 80, "Explicitly unsafe YAML")
	r.register("yaml_full_load", `(?i)yaml\.full_load\s*\(`, cat, 70, "Full YAML load (unsafe)")

	// Java
	r.register("java_objectinputstream", `(?i)ObjectInputStream\s*\(`, cat, 80, "Java deserialization")
	r.register("java_xmldecoder", `(?i)XMLDecoder\s*\(`, cat, 75, "XML deserialization")
	r.register("java_xstream", `(?i)XStream\s*\(\)\.fromXML`, cat, 75, "XStream deserialization")
	r.register("java_readobject", `(?i)readObject\s*\(\s*\)`, cat, 70, "Java readObject")
	r.register("java_readunshared", `(?i)readUnshared\s*\(\s*\)`, cat, 70, "Java readUnshared")

	// PHP
	r.register("php_unserialize", `(?i)unserialize\s*\(`, cat, 80, "PHP unserialize")
	r.register("php_maybe_unserialize", `(?i)maybe_unserialize\s*\(`, cat, 70, "WordPress unserialize")

	// Ruby
	r.register("ruby_marshal", `(?i)Marshal\.load\s*\(`, cat, 80, "Ruby Marshal load")
	r.register("ruby_yaml", `(?i)YAML\.load\s*\(`, cat, 75, "Ruby YAML load")
	r.register("ruby_psych", `(?i)Psych\.load\s*\(`, cat, 75, "Ruby Psych load")

	// .NET
	r.register("dotnet_binaryformatter", `(?i)BinaryFormatter\s*\(\)\.Deserialize`, cat, 85, ".NET BinaryFormatter")
	r.register("dotnet_soapformatter", `(?i)SoapFormatter\s*\(\)\.Deserialize`, cat, 80, ".NET SoapFormatter")
	r.register("dotnet_netdatacontract", `(?i)NetDataContractSerializer`, cat, 75, ".NET serializer")
	r.register("dotnet_losformatter", `(?i)LosFormatter\s*\(\)\.Deserialize`, cat, 80, ".NET LosFormatter")
	r.register("dotnet_objectstateformatter", `(?i)ObjectStateFormatter`, cat, 75, ".NET ObjectStateFormatter")

	// JavaScript/Node.js
	r.register("node_serialize", `(?i)node-serialize`, cat, 85, "node-serialize (vulnerable)")
	r.register("serialize_javascript", `(?i)serialize-javascript.*\(.*function`, cat, 80, "Function in serialization")
	r.register("funcster", `(?i)funcster`, cat, 80, "Funcster (dangerous)")

	// Generic
	r.register("python_reduce", `(?i)__reduce__\s*\(`, cat, 75, "Python __reduce__ method")
	r.register("python_setstate", `(?i)__setstate__\s*\(`, cat, 70, "Python __setstate__")
	r.register("java_serial_base64", `(?i)rO0AB`, cat, 80, "Base64 Java serialized object")
	r.register("java_serial_hex", `(?i)aced0005`, cat, 80, "Java serialization magic bytes")
}

// --- SSRF PATTERNS (PRE-HOOK) ---
func (r *Registry) registerSSRFPatterns() {
	cat := CategorySSRF

	// Cloud metadata endpoints
	r.register("aws_metadata", `https?://169\.254\.169\.254`, cat, 90, "AWS metadata endpoint")
	r.register("gcp_metadata", `https?://metadata\.google\.internal`, cat, 90, "GCP metadata endpoint")
	r.register("azure_metadata", `https?://metadata\.azure\.com`, cat, 90, "Azure metadata endpoint")
	r.register("alibaba_metadata", `https?://100\.100\.100\.200`, cat, 90, "Alibaba Cloud metadata")

	// Kubernetes
	r.register("k8s_default", `https?://kubernetes\.default`, cat, 85, "Kubernetes default service")
	r.register("k8s_default_svc", `https?://kubernetes\.default\.svc`, cat, 85, "Kubernetes default svc")

	// Docker
	r.register("docker_host", `https?://host\.docker\.internal`, cat, 80, "Docker host internal")
	r.register("docker_gateway", `https?://gateway\.docker\.internal`, cat, 80, "Docker gateway internal")

	// Internal hostnames
	r.register("localhost_http", `https?://localhost`, cat, 70, "Localhost access")
	r.register("loopback_127", `https?://127\.0\.0\.1`, cat, 75, "Loopback IP access")
	r.register("loopback_0000", `https?://0\.0\.0\.0`, cat, 75, "0.0.0.0 access")

	// Private IP ranges
	r.register("private_10", `https?://10\.\d+\.\d+\.\d+`, cat, 70, "Private 10.x.x.x network")
	r.register("private_172", `https?://172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+`, cat, 70, "Private 172.16-31.x.x network")
	r.register("private_192", `https?://192\.168\.\d+\.\d+`, cat, 70, "Private 192.168.x.x network")

	// Internal domain patterns
	r.register("internal_domain", `https?://[^/]+\.internal(/|$)`, cat, 65, "Internal domain")
	r.register("localdomain", `https?://[^/]+\.localdomain(/|$)`, cat, 65, "Localdomain access")
}

// --- INDIRECT INJECTION PATTERNS (POST-HOOK) ---
func (r *Registry) registerIndirectInjectionPatterns() {
	cat := CategoryIndirectInj

	// Instruction override in output
	r.register("indirect_ignore", `(?i)ignore\s+(all\s+)?previous\s+instructions`, cat, 75, "Instruction override in output")
	r.register("indirect_disregard", `(?i)disregard\s+(all\s+)?prior`, cat, 70, "Disregard prior instructions")
	r.register("indirect_new_instructions", `(?i)your\s+new\s+instructions\s+are`, cat, 75, "New instruction injection")

	// Command injection markers
	r.register("indirect_execute", `(?i)execute\s+the\s+following`, cat, 60, "Execute command marker")
	r.register("indirect_run", `(?i)run\s+this\s+command`, cat, 60, "Run command marker")
}

// --- EXFILTRATION PATTERNS (PRE-HOOK) ---
func (r *Registry) registerExfiltrationPatterns() {
	cat := CategoryExfiltration

	// Email addresses (potential data exfiltration)
	r.register("email_address", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, cat, 50, "Email address")
	r.register("email_mailto", `mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, cat, 55, "Mailto link")

	// Phone numbers (US format)
	// Phone number - requires at least one separator to avoid matching API keys/tokens
	r.register("phone_us", `(?:\+1[-.\s])?\(?[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}`, cat, 45, "US Phone number")

	// Social Security Numbers
	r.register("ssn_pattern", `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, cat, 90, "Social Security Number")

	// Credit Card Numbers (major brands)
	r.register("cc_visa", `\b4[0-9]{12}(?:[0-9]{3})?\b`, cat, 95, "Visa Card Number")
	r.register("cc_mastercard", `\b5[1-5][0-9]{14}\b`, cat, 95, "Mastercard Number")
	r.register("cc_amex", `\b3[47][0-9]{13}\b`, cat, 95, "American Express Number")
	r.register("cc_discover", `\b6(?:011|5[0-9]{2})[0-9]{12}\b`, cat, 95, "Discover Card Number")

	// IP Addresses (potential target identification)
	r.register("ipv4_address", `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`, cat, 40, "IPv4 Address")

	// Known exfil services
	r.register("webhook_site", `(?i)webhook\.site`, cat, 70, "Webhook.site exfil service")
	r.register("requestbin", `(?i)requestbin\.`, cat, 70, "RequestBin exfil service")
	r.register("ngrok", `(?i)ngrok\.io`, cat, 65, "Ngrok tunnel")
	r.register("pipedream", `(?i)pipedream\.net`, cat, 70, "Pipedream exfil service")
	r.register("hookbin", `(?i)hookbin\.com`, cat, 70, "Hookbin exfil service")
	r.register("beeceptor", `(?i)beeceptor\.com`, cat, 70, "Beeceptor exfil service")
	r.register("requestcatcher", `(?i)requestcatcher\.com`, cat, 70, "Request Catcher exfil service")
	r.register("canarytokens", `(?i)canarytokens\.com`, cat, 60, "Canary tokens service")
	r.register("burpcollaborator", `(?i)burpcollaborator\.net`, cat, 75, "Burp Collaborator")
	r.register("interactsh", `(?i)interactsh\.com`, cat, 75, "Interactsh OAST service")
	r.register("oast_services", `(?i)oast\.`, cat, 70, "Out-of-band testing services")
	r.register("oastify", `(?i)oastify\.com`, cat, 70, "Oastify OAST service")
}

// --- INJECTION ATTACK PATTERNS (ML/SCORING) ---
func (r *Registry) registerInjectionAttackPatterns() {
	cat := CategoryInjectionAttack

	// Shell injection in output
	r.register("shell_rm_rf", `;\s*rm\s+-rf\s+/`, cat, 85, "Dangerous rm -rf command")
	r.register("shell_rm_and", `&&\s*rm\s+-rf`, cat, 85, "Chained rm -rf command")
	r.register("shell_rm_or", `\|\|\s*rm\s+-rf`, cat, 85, "Conditional rm -rf command")
	r.register("shell_pipe_bash", `\|\s*(bash|sh|zsh|ksh|csh)(\s|$)`, cat, 70, "Pipe to shell")
	r.register("shell_curl_bash", `curl[^|]*\|\s*(bash|sh)`, cat, 80, "Curl pipe to bash")
	r.register("shell_wget_bash", `wget[^|]*\|\s*(bash|sh)`, cat, 80, "Wget pipe to bash")
	r.register("shell_cmd_subst", `\$\([^)]{10,}\)`, cat, 50, "Command substitution")
	r.register("shell_backticks", "`[^`]{10,}`", cat, 50, "Backtick command substitution")
	r.register("shell_nested_subst", `\$\{[^}]*\$\([^)]+\)}`, cat, 60, "Nested command substitution")

	// Reverse shell
	r.register("reverse_shell_tcp", `/dev/tcp/\d+\.\d+\.\d+\.\d+`, cat, 90, "Reverse shell /dev/tcp")
	r.register("reverse_shell_nc", `nc\s+-[elp]+\s+\d+`, cat, 85, "Netcat reverse shell")
	r.register("reverse_shell_bash", `bash\s+-i\s+>&\s*/dev/tcp`, cat, 90, "Bash interactive reverse shell")

	// SQL injection
	r.register("sql_drop", `(?i)';\s*DROP\s+TABLE`, cat, 85, "SQL DROP TABLE injection")
	r.register("sql_delete", `(?i)';\s*DELETE\s+FROM`, cat, 80, "SQL DELETE injection")
	r.register("sql_truncate", `(?i)';\s*TRUNCATE\s+TABLE`, cat, 85, "SQL TRUNCATE injection")
	r.register("sql_update", `(?i)';\s*UPDATE\s+\w+\s+SET`, cat, 75, "SQL UPDATE injection")
	r.register("sql_union", `(?i)UNION\s+(ALL\s+)?SELECT\s+`, cat, 70, "SQL UNION injection")
	r.register("sql_union_null", `(?i)UNION\s+SELECT\s+NULL`, cat, 75, "SQL UNION SELECT NULL")
	r.register("sql_boolean_or", `(?i)'\s*OR\s+'1'\s*=\s*'1`, cat, 65, "SQL boolean OR injection")
	r.register("sql_boolean_and", `(?i)'\s*AND\s+'1'\s*=\s*'1`, cat, 60, "SQL boolean AND injection")
	r.register("sql_time_waitfor", `(?i);\s*WAITFOR\s+DELAY`, cat, 70, "SQL time-based WAITFOR")
	r.register("sql_time_sleep", `(?i);\s*SLEEP\s*\(\d+\)`, cat, 70, "SQL time-based SLEEP")
	r.register("sql_benchmark", `(?i)BENCHMARK\s*\(\d+,`, cat, 65, "SQL BENCHMARK")
}

// --- JAILBREAK PATTERNS (ML/SCORING) ---
func (r *Registry) registerJailbreakPatterns() {
	cat := CategoryJailbreak

	// Persona injection
	r.register("jailbreak_evil", `(?i)you\s+are\s+now\s+(a|an|the)?\s*(evil|unrestricted|jailbroken)`, cat, 80, "Evil persona injection")
	r.register("jailbreak_no_restrict", `(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions`, cat, 75, "No restrictions prompt")
	r.register("jailbreak_pretend", `(?i)pretend\s+(you\s+are|to\s+be)\s+(a|an)?\s*(hacker|attacker)`, cat, 75, "Pretend to be attacker")

	// DAN and similar
	r.register("jailbreak_dan", `(?i)\bDAN\b.*mode`, cat, 70, "DAN jailbreak")
	r.register("jailbreak_developer", `(?i)developer\s+mode`, cat, 65, "Developer mode jailbreak")
	r.register("jailbreak_sudo", `(?i)sudo\s+mode`, cat, 65, "Sudo mode jailbreak")

	// Context manipulation
	r.register("jailbreak_test", `(?i)the\s+following\s+is\s+(a\s+)?test`, cat, 40, "Test context manipulation")
	r.register("jailbreak_debug", `(?i)debug\s+mode\s+(activated|enabled)`, cat, 60, "Debug mode activation")
	r.register("jailbreak_system_tag", `(?i)\[system\]|\<system\>`, cat, 65, "System tag injection")
}

// --- PROMPT EXTRACTION PATTERNS (ML/SCORING) ---
func (r *Registry) registerPromptExtractionPatterns() {
	cat := CategoryPromptExtraction

	r.register("extract_repeat", `(?i)repeat\s+(everything|all|your)\s+(above|instructions)`, cat, 75, "Repeat instructions prompt")
	r.register("extract_output", `(?i)output\s+your\s+system\s+prompt`, cat, 80, "Output system prompt")
	r.register("extract_show", `(?i)show\s+me\s+your\s+(system\s+)?prompt`, cat, 75, "Show system prompt")
	r.register("extract_reveal", `(?i)reveal\s+(your|the)\s+(system\s+)?prompt`, cat, 75, "Reveal prompt")
	r.register("extract_what_prompt", `(?i)what\s+is\s+your\s+(system\s+)?prompt`, cat, 70, "What is prompt")
	r.register("extract_instructions", `(?i)what\s+are\s+your\s+instructions`, cat, 70, "What are instructions")
}
