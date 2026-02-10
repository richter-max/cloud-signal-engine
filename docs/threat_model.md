# Threat Model

## Overview

This document outlines the security threats SignalForge is designed to detect, the attack scenarios covered by each detection rule, and the current limitations and blind spots.

## Threat Landscape

SignalForge focuses on **cloud-native security threats** targeting:
- **Authentication systems** (login endpoints, SSO, federated identity)
- **IAM/Permissions** (role escalations, policy changes)
- **API abuse** (rate limiting, DoS, credential stuffing)
- **Account compromise** (impossible travel, unusual access patterns)

## Attack Scenarios by Detection Rule

### 1. Brute Force Attacks

**Threat:** Attacker attempts to guess user passwords through repeated login attempts.

**Attack Flow:**
1. Attacker obtains username (public, data breach, guessing)
2. Iterates through password list (rockyou.txt, common passwords)
3. Submits login attempts rapidly
4. Success → account compromise

**Detection Coverage:**
- ✅ Detects multiple failed attempts from same IP
- ✅ Identifies targeted users
- ✅ Captures time-based attack patterns

**Limitations:**
- ❌ Distributed brute force (many IPs) not detected by this rule alone
- ❌ Slow and low attacks (<5 attempts per 15 min) evade threshold
- ❌ Account lockout (external control) not modeled

**Mitigation Recommendations:**
- Implement account lockout after 3-5 failed attempts
- Add CAPTCHA after 2 failures
- Enforce strong password policies
- Enable MFA (multi-factor authentication)

---

### 2. Password Spray Attacks

**Threat:** Attacker tries common passwords against many accounts to avoid account lockout.

**Attack Flow:**
1. Attacker enumerates usernames (LDAP, public directories)
2. Selects common password (e.g., "Winter2024!", "Company123")
3. Attempts login for 100+ users with same password
4. Success → account compromise without triggering lockout

**Detection Coverage:**
- ✅ Detects single IP targeting many users
- ✅ Effective against concentrated spray attacks
- ✅ Captures full user list for investigation

**Limitations:**
- ❌ Distributed spray (attackers use rotating IPs) harder to detect
- ❌ Very slow sprays (1 user per minute) may evade window
- ❌ Legitimate SSO gateways may look similar

**Mitigation Recommendations:**
- Monitor authentication patterns across all IPs (aggregate detection)
- Implement geo-fencing (block unexpected countries)
- Use risk-based authentication (device fingerprinting)

---

### 3. Credential Compromise (Impossible Travel)

**Threat:** Stolen credentials used from different geographic locations.

**Attack Flow:**
1. Credential compromised (phishing, malware, data breach)
2. Attacker logs in from their location
3. Legitimate user also logs in from their location
4. Both logins appear within short time window

**Detection Coverage:**
- ✅ Detects geographically impossible login sequences
- ✅ Provides time/distance evidence
- ✅ Identifies compromised accounts quickly

**Limitations:**
- ❌ VPN users appear to "teleport" (false positives)
- ❌ MVP uses IP heuristic (not real GeoIP data)
- ❌ Attackers using same VPN as victim go undetected
- ❌ Requires both legitimate and illegitimate logins to trigger

**Mitigation Recommendations:**
- Integrate MaxMind GeoIP2 for accurate geolocation
- Allowlist known VPN endpoints
- Combine with device fingerprinting (new device = higher risk)
- Correlate with threat intelligence (known bad IPs)

---

### 4. Automated Abuse (Suspicious User Agents)

**Threat:** Bots, scrapers, or automated tools abuse APIs.

**Attack Flow:**
1. Attacker uses automated tool (curl, python-requests)
2. Rapidly scrapes data or tests vulnerabilities
3. May combine with credential stuffing or fuzzing

**Detection Coverage:**
- ✅ Detects non-browser user agents
- ✅ Identifies automation patterns
- ✅ Useful for discovering unauthorized API usage

**Limitations:**
- ❌ Easily evaded by spoofing user agent
- ❌ Legitimate automation (CI/CD, monitoring) triggers false positives
- ❌ Mobile apps may use custom user agents

**Mitigation Recommendations:**
- Combine with rate limiting (detect behavior, not just UA)
- Require API keys for automation
- Use bot detection services (hCaptcha, reCAPTCHA)

---

### 5. API Abuse / DoS

**Threat:** Excessive requests overwhelm service or scrape data at scale.

**Attack Flow:**
1. Attacker identifies valuable API endpoints
2. Sends high volume of requests
3. Either DoS (service degradation) or data exfiltration

**Detection Coverage:**
- ✅ Detects rate spikes from individual IPs or users
- ✅ Calculates requests/second for severity assessment
- ✅ Identifies both authenticated and unauthenticated abuse

**Limitations:**
- ❌ Distributed attacks (botnet) harder to detect per-IP
- ❌ "Slow and low" attacks (sustained but below threshold) evade
- ❌ Legitimate traffic spikes (Black Friday) may false positive

**Mitigation Recommendations:**
- Implement rate limiting at API gateway (nginx, Cloudflare)
- Use adaptive thresholds (baseline + standard deviation)
- Differentiate by endpoint (some APIs are naturally high-traffic)

---

### 6. Privilege Escalation / Insider Threats

**Threat:** Unauthorized elevation of user permissions, compromised admin accounts.

**Attack Flow:**
1. Attacker gains initial access (compromised low-privilege account)
2. Exploits IAM misconfiguration or social engineering
3. Grants themselves admin role
4. Full environment compromise

**Detection Coverage:**
- ✅ Detects any IAM/permission change
- ✅ Captures who made change and what changed
- ✅ High severity for admin actions

**Limitations:**
- ❌ Legitimate admin changes trigger alerts (high false positive rate)
- ❌ No correlation with change tickets or approval workflows
- ❌ Delayed detection (not real-time)

**Mitigation Recommendations:**
- Implement just-in-time (JIT) access
- Require approval workflow for privilege changes
- Correlate alerts with ITSM tickets (ServiceNow, Jira)
- Use anomaly detection (ML-based)

---

## Coverage Matrix

| Threat Type | Detection Rule | Coverage | Evasion Difficulty |
|-------------|---------------|----------|-------------------|
| Password Guessing | Brute Force | High | Medium (distribute IPs) |
| Credential Spray | Password Spray | High | Medium (slow rate) |
| Account Takeover | Impossible Travel | Medium | Low (use same VPN) |
| Bot Activity | Suspicious UA | Low | Very Low (spoof UA) |
| DoS/Scraping | API Abuse | Medium | Medium (distribute, slow) |
| Privilege Abuse | Priv Escalation | High | Hard (requires legit change) |

## Blind Spots & Future Enhancements

### Current Blind Spots

1. **Distributed Attacks**
   - **Gap:** Rules focus on per-IP or per-user aggregation
   - **Mitigation:** Add cross-IP correlation (e.g., many IPs targeting same user)

2. **Machine Learning Anomalies**
   - **Gap:** No baseline behavior modeling
   - **Mitigation:** Implement ML-based anomaly detection (clustering, outlier detection)

3. **Lateral Movement**
   - **Gap:** No detection of post-compromise movement (pivot, lateral spread)
   - **Mitigation:** Add network flow analysis, privilege usage tracking

4. **Data Exfiltration**
   - **Gap:** High-volume data downloads not detected
   - **Mitigation:** Track egress patterns (bytes out, unusual file access)

5. **Insider Threats (Behavioral)**
   - **Gap:** Trusted users with legitimate access abusing it
   - **Mitigation:** User behavior analytics (UBA), peer group analysis

### Planned Enhancements (v0.2.0+)

- **ML-based Detection**: LSTM for time-series anomalies
- **Correlation Engine**: Chain related alerts (multi-stage attacks)
- **GeoIP Integration**: MaxMind GeoIP2 for accurate impossible travel
- **Device Fingerprinting**: Detect new devices, OS changes
- **Threat Intel Feeds**: Integrate AlienVault OTX, abuse.ch for known bad IPs
- **Behavioral Baselines**: Per-user/per-IP normal behavior profiles

## MITRE ATT&CK Coverage

SignalForge currently covers the following techniques:

| Technique | Rule | Status |
|-----------|------|--------|
| T1110 - Brute Force | Brute Force Login | ✅ Covered |
| T1110.003 - Password Spraying | Password Spray | ✅ Covered |
| T1078 - Valid Accounts | Impossible Travel | ✅ Covered |
| T1071 - Application Layer Protocol | Suspicious UA | ⚠️ Partial |
| T1498 - Network Denial of Service | API Abuse | ⚠️ Partial |
| T1078.004 - Cloud Accounts | Privilege Escalation | ✅ Covered |
| T1548 - Abuse Elevation Control | Privilege Escalation | ✅ Covered |

**Not Currently Covered:**
- T1565 - Data Manipulation
- T1557 - Adversary-in-the-Middle
- T1021 - Remote Services
- T1562 - Impair Defenses
- T1531 - Account Access Removal

## Deployment Security

### Internal Deployment Assumptions

SignalForge MVP assumes **internal deployment** (corporate network, trusted environment):
- ✅ No authentication on API endpoints
- ✅ No encryption at rest (SQLite database)
- ✅ No audit logging of analyst actions

### Production Security Requirements

For external or multi-tenant deployment:
- ❌ **Authentication**: JWT bearer tokens, API keys per source
- ❌ **Authorization**: RBAC (analyst, admin, read-only)
- ❌ **Encryption**: TLS for API, encryption at rest for database
- ❌ **Audit Logging**: Track who viewed/modified alerts
- ❌ **Rate Limiting**: Protect APIs from abuse
- ❌ **Input Validation**: Stricter limits on payload sizes

## Compliance Considerations

SignalForge can support compliance requirements:

- **SOC 2**: Logging, access controls, change management
- **PCI-DSS**: Brute force detection (Req 8.1.6), access logs (Req 10)
- **GDPR**: Data retention policies, audit trails
- **ISO 27001**: Security monitoring, incident response

## Threat Actor Profiling

SignalForge is designed to detect:

- ✅ **External Attackers** (automation, distributed attacks)
- ✅ **Script Kiddies** (noisy, high-volume attacks)
- ⚠️ **APT Groups** (partial - lacks sophisticated correlation)
- ⚠️ **Insider Threats** (partial - lacks behavioral analytics)
- ❌ **Supply Chain Attacks** (not covered)
