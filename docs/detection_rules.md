# Detection Rules Reference

## Overview

SignalForge includes 6 production-ready detection rules mapped to the MITRE ATT&CK framework. Each rule analyzes time-windowed event data to identify specific attack patterns.

## Rule Catalog

### 1. Brute Force Login Detection

**Rule ID:** `brute_force_login`

**Description:** Detects multiple failed login attempts from the same source IP address within a short time window, indicating a brute force attack attempting to guess user credentials.

**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

**Severity:** HIGH

**Time Window:** 15 minutes

**Threshold:** 5+ failed login attempts

**Detection Logic:**
```sql
SELECT source_ip, COUNT(*) as failures
FROM events
WHERE action IN ('user.login', 'login', 'signin')
  AND outcome = 'failure'
  AND timestamp BETWEEN window_start AND window_end
GROUP BY source_ip
HAVING COUNT(*) >= 5
```

**Evidence Collected:**
- Source IP address
- Number of failed attempts
- List of targeted usernames
- Event IDs (for forensic investigation)
- Time span of attack
- First and last attempt timestamps

**Example Evidence:**
```json
{
  "source_ip": "203.0.113.45",
  "attempt_count": 15,
  "targeted_users": ["alice", "bob"],
  "event_ids": [123, 124, 125, ...],
  "first_attempt": "2024-02-09T20:00:00Z",
  "last_attempt": "2024-02-09T20:14:30Z",
  "time_span_seconds": 870
}
```

**Tuning Guidance:**
- **Corporate VPN**: If corporate VPN gateway retries failed authentications, add to allowlist
- **Threshold**: Increase to 10+ for less sensitive environments
- **Time Window**: Extend to 30 minutes for slower attacks

---

### 2. Password Spray Detection

**Rule ID:** `password_spray`

**Description:** Detects a single IP address attempting to authenticate as many different users, indicating a password spray attack trying common passwords across multiple accounts.

**MITRE ATT&CK:** [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

**Severity:** CRITICAL

**Time Window:** 30 minutes

**Threshold:** 10+ unique users targeted

**Detection Logic:**
```sql
SELECT source_ip, COUNT(DISTINCT actor) as unique_users
FROM events
WHERE action IN ('user.login', 'login', 'signin')
  AND timestamp BETWEEN window_start AND window_end
GROUP BY source_ip
HAVING COUNT(DISTINCT actor) >= 10
```

**Evidence Collected:**
- Source IP address
- Number of unique users targeted
- Total login attempts
- List of targeted usernames
- Event IDs
- Time span

**Example Evidence:**
```json
{
  "source_ip": "198.51.100.50",
  "unique_users_targeted": 15,
  "total_attempts": 18,
  "targeted_users": ["alice", "bob", "charlie", ...],
  "event_ids": [200, 201, 202, ...],
  "first_attempt": "2024-02-09T20:00:00Z",
  "last_attempt": "2024-02-09T20:25:00Z"
}
```

**Tuning Guidance:**
- **Shared Services**: If load balancer IPs appear, use X-Forwarded-For header
- **Threshold**: Adjust based on organization size (larger orgs may want 20+)
- **Allowlist**: Add federated SSO gateways that legitimately authenticate many users

---

### 3. Impossible Travel Detection

**Rule ID:** `impossible_travel`

**Description:** Detects when the same user successfully logs in from geographically distant locations within a timeframe that makes physical travel impossible, indicating credential compromise.

**MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)

**Severity:** HIGH

**Time Window:** 60 minutes

**Threshold:** Same user from IPs >500km apart in <2 hours

**Detection Logic:**
```python
# Pseudocode
for each user with multiple logins:
    for consecutive login pairs:
        distance = geoip_distance(ip1, ip2)
        time_delta = timestamp2 - timestamp1
        if distance > 500km and time_delta < 2 hours:
            alert()
```

**Evidence Collected:**
- Actor (username)
- Location 1 (IP, timestamp, event ID)
- Location 2 (IP, timestamp, event ID)
- Estimated distance (km)
- Time delta (hours)
- Impossible speed (km/h)

**Example Evidence:**
```json
{
  "actor": "bob.jones",
  "location1": {
    "ip": "192.168.1.11",
    "timestamp": "2024-02-09T20:00:00Z",
    "event_id": 300
  },
  "location2": {
    "ip": "85.123.45.67",
    "timestamp": "2024-02-09T20:30:00Z",
    "event_id": 301
  },
  "estimated_distance_km": 2500,
  "time_delta_hours": 0.5,
  "impossible_speed_kmh": 5000
}
```

**Current Limitations (MVP):**
- Uses IP prefix heuristic (not real GeoIP)
- Assumes different /8 = different country

**Production Enhancement:**
- Integrate MaxMind GeoIP2 for accurate geolocation
- Account for VPN usage (allowlist known VPN IPs)
- Consider timezone-based logic (login at reasonable local time)

**Tuning Guidance:**
- **Remote Workers**: Allowlist users who frequently travel
- **VPN Users**: IPs may jump between VPN endpoints
- **Distance Threshold**: Adjust based on geography (500km ≈ US state-to-state)

---

### 4. Suspicious User-Agent Detection

**Rule ID:** `suspicious_user_agent`

**Description:** Detects requests with user agents indicating automated tools, bots, or missing user agents, suggesting unauthorized automation or scraping.

**MITRE ATT&CK:** [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

**Severity:** MEDIUM

**Time Window:** 15 minutes

**Threshold:** 5+ requests with suspicious UA

**Suspicious Patterns:**
- Empty user agent
- `curl`, `wget`
- `python-requests`, `python-urllib`
- `scrapy`, `bot`, `crawler`, `spider`
- `httpx`, `http.client`

**Detection Logic:**
```python
# Regex patterns
PATTERNS = [r"^$", r"curl", r"wget", r"python-requests", ...]

for event in events:
    if any(pattern.match(event.user_agent)):
        suspicious.append(event)

if len(suspicious) >= 5:
    alert()
```

**Evidence Collected:**
- User agent string
- Request count
- Actors (if authenticated)
- Source IPs
- Event IDs
- Matched pattern

**Example Evidence:**
```json
{
  "user_agent": "curl/7.68.0",
  "request_count": 20,
  "actors": ["api.bot.user"],
  "source_ips": ["45.76.123.98"],
  "event_ids": [400, 401, ...],
  "pattern_matched": "curl"
}
```

**Tuning Guidance:**
- **Monitoring Tools**: Allowlist known health check tools (Pingdom, UptimeRobot)
- **Legitimate Bots**: Some APIs are used by automation (CI/CD, internal scripts)
- **Pattern Additions**: Add custom patterns for new bot types

---

### 5. API Abuse / Rate Spike Detection

**Rule ID:** `api_abuse`

**Description:** Detects abnormally high request rates from a single IP or user, indicating potential DoS attacks, credential stuffing, or data scraping.

**MITRE ATT&CK:** [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)

**Severity:** MEDIUM

**Time Window:** 5 minutes

**Threshold:** 100+ requests

**Detection Logic:**
```sql
-- By IP
SELECT source_ip, COUNT(*) as request_count
FROM events
WHERE timestamp BETWEEN window_start AND window_end
GROUP BY source_ip
HAVING COUNT(*) >= 100

-- By Actor (authenticated abuse)
SELECT actor, COUNT(*) as request_count
FROM events
WHERE timestamp BETWEEN window_start AND window_end
GROUP BY actor
HAVING COUNT(*) >= 100
```

**Evidence Collected:**
- Source IP or actor
- Request count
- Unique actions (API endpoints hit)
- Requests per second
- Time span

**Example Evidence:**
```json
{
  "source_ip": "45.76.123.98",
  "request_count": 150,
  "unique_actions": 5,
  "requests_per_second": 30,
  "first_request": "2024-02-09T20:00:00Z",
  "last_request": "2024-02-09T20:05:00Z"
}
```

**Tuning Guidance:**
- **Batch Processing**: Legitimate batch jobs may spike temporarily (allowlist)
- **Load Testing**: Add environments to allowlist during planned tests
- **Threshold**: Adjust based on typical user behavior (100 = conservative, 500 = lenient)
- **Time Window**: Shorten to 1 minute for tighter detection

---

### 6. Privilege Escalation Detection

**Rule ID:** `privilege_escalation`

**Description:** Detects IAM role/permission changes, user elevations, and administrative actions that could indicate unauthorized privilege escalation or insider threats.

**MITRE ATT&CK:** 
- [T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

**Severity:** CRITICAL (admin actions) / HIGH (role changes)

**Time Window:** 60 minutes

**Threshold:** Any privilege-related action triggers alert

**Monitored Actions:**
- `iam.role.create`, `iam.role.update`, `iam.role.delete`
- `iam.role.attach_policy`, `iam.role.detach_policy`
- `iam.user.create`, `iam.user.update`, `iam.user.promote`
- `iam.user.add_to_group`
- `iam.policy.create`, `iam.policy.attach`
- `permissions.grant`, `permissions.modify`

**Detection Logic:**
```sql
SELECT *
FROM events
WHERE action LIKE '%iam%' OR action LIKE '%permission%'
  AND timestamp BETWEEN window_start AND window_end
```

**Evidence Collected:**
- Actor (who made the change)
- Action performed
- Resource (target role/user/policy)
- Outcome (success/failure)
- Source IP
- Timestamp
- Event ID

**Example Evidence:**
```json
{
  "actor": "admin.user",
  "action": "iam.role.attach_policy",
  "resource": "super-admin-role",
  "outcome": "success",
  "source_ip": "192.168.1.10",
  "timestamp": "2024-02-09T20:15:00Z",
  "event_id": 500
}
```

**Tuning Guidance:**
- **Automation**: Allowlist Terraform/IaC service accounts
- **Change Management**: Correlate with change tickets (future enhancement)
- **Time-based**: Expected changes during business hours vs. off-hours

---

## Adding Custom Rules

### Step 1: Create Rule Class

```python
# backend/app/services/rules/my_custom_rule.py

from .base import DetectionRule

class MyCustomRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "my_custom_rule"
    
    @property
    def name(self) -> str:
        return "My Custom Detection"
    
    @property
    def description(self) -> str:
        return "Detects XYZ pattern"
    
    @property
    def severity(self) -> str:
        return "high"
    
    @property
    def window_minutes(self) -> int:
        return 15
    
    def detect(self, db, window_start, window_end):
        # Query events
        events = db.query(Event).filter(...).all()
        
        # Detection logic
        alerts = []
        if condition_met:
            alerts.append({
                "rule_id": self.rule_id,
                "severity": self.severity,
                "summary": "Alert summary",
                "evidence": {...},
                "alert_time": window_end,
                "window_start": window_start,
                "window_end": window_end,
            })
        
        return alerts
```

### Step 2: Register in Detection Engine

```python
# backend/app/services/detection_engine.py

from .rules.my_custom_rule import MyCustomRule

DETECTION_RULES = [
    BruteForceRule(),
    PasswordSprayRule(),
    # ... existing rules
    MyCustomRule(),  # Add here
]
```

### Step 3: Write Tests

```python
# backend/tests/test_rules.py

def test_my_custom_rule(db_session):
    rule = MyCustomRule()
    # Create test events
    # Run detection
    alerts = rule.detect(db_session, window_start, window_end)
    assert len(alerts) == expected
```

## Rule Performance Optimization

### Query Optimization
- Use indexes on frequently queried fields
- Limit GROUP BY aggregations to indexed columns
- Use `EXPLAIN` to analyze query plans

### Incremental Detection
```python
# Track last processed event ID
last_id = get_last_processed_id()
events = db.query(Event).filter(Event.id > last_id).all()
```

### Parallel Execution
```python
# Use ThreadPoolExecutor for rule execution
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=6) as executor:
    futures = [executor.submit(rule.detect, db, start, end) for rule in rules]
    results = [f.result() for f in futures]
```
