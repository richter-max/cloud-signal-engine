# Demo Scenarios

This document describes the pre-generated demo scenarios included in SignalForge to showcase each detection rule.

## Overview

The demo log generator (`examples/generators/generate_demo_logs.py`) creates realistic security event logs with both normal user activity and attack scenarios.

## Included Scenarios

### Scenario 1: Brute Force Attack

**Objective:** Demonstrate detection of password guessing attacks

**Attack Details:**
- Attacker IP: `203.0.113.45`
- Target user: `alice.smith`
- Attack pattern: 15 failed login attempts in 10 minutes
- Expected detection window: 15 minutes

**Expected Alert:**
```json
{
  "rule_id": "brute_force_login",
  "severity": "high",
  "summary": "Brute force attack detected: 15 failed login attempts from 203.0.113.45",
  "evidence": {
    "source_ip": "203.0.113.45",
    "attempt_count": 15,
    "targeted_users": ["alice.smith"],
    "first_attempt": "2024-02-09T20:10:00Z",
    "last_attempt": "2024-02-09T20:19:45Z",
    "time_span_seconds": 585
  }
}
```

**Triage Recommendation:**
1. Check if IP is known malicious (threat intel)
2. Verify user `alice.smith` for compromise
3. Block IP at firewall
4. Force password reset for targeted user

---

### Scenario 2: Password Spray Attack

**Objective:** Demonstrate detection of wide-spread password attempts

**Attack Details:**
- Attacker IP: `198.51.100.50`
- Targeted users: 15 different accounts
- Attack pattern: 1-2 attempts per user over 25 minutes
- Expected detection window: 30 minutes

**Expected Alert:**
```json
{
  "rule_id": "password_spray",
  "severity": "critical",
  "summary": "Password spray attack detected: 198.51.100.50 targeted 15 different users",
  "evidence": {
    "source_ip": "198.51.100.50",
    "unique_users_targeted": 15,
    "total_attempts": 18,
    "targeted_users": ["alice.smith", "bob.jones", "charlie.davis", ...]
  }
}
```

**Triage Recommendation:**
1. Block attacker IP
2. Force MFA re-enrollment for all targeted users
3. Audit for any successful logins from this IP
4. Check other IPs for similar patterns (distributed spray)

---

### Scenario 3: Impossible Travel

**Objective:** Demonstrate detection of geographically impossible logins

**Attack Details:**
- User: `bob.jones`
- Location 1: US (`192.168.1.11`) at T+0
- Location 2: EU (`85.123.45.67`) at T+30 minutes
- Distance: ~2500 km
- Time delta: 0.5 hours → 5000 km/h (impossible)

**Expected Alert:**
```json
{
  "rule_id": "impossible_travel",
  "severity": "high",
  "summary": "Impossible travel detected: bob.jones logged in from 192.168.1.11 and 85.123.45.67 within 0.5 hours",
  "evidence": {
    "actor": "bob.jones",
    "location1": {"ip": "192.168.1.11", "timestamp": "2024-02-09T20:15:00Z"},
    "location2": {"ip": "85.123.45.67", "timestamp": "2024-02-09T20:45:00Z"},
    "estimated_distance_km": 2500,
    "time_delta_hours": 0.5,
    "impossible_speed_kmh": 5000
  }
}
```

**Triage Recommendation:**
1. Contact user `bob.jones` to verify both logins
2. If unrecognized, treat as account compromise
3. Force password reset and logout all sessions
4. Review user's recent activity for data access

---

### Scenario 4: Suspicious User-Agent

**Objective:** Demonstrate detection of automated tools

**Attack Details:**
- User agent: `curl/7.68.0`
- Source IP: `45.76.123.98`
- Activity: 20 API requests in 10 minutes
- Pattern: Automated data scraping

**Expected Alert:**
```json
{
  "rule_id": "suspicious_user_agent",
  "severity": "medium",
  "summary": "Suspicious user agent detected: 20 requests with automated/suspicious UA",
  "evidence": {
    "user_agent": "curl/7.68.0",
    "request_count": 20,
    "actors": ["api.bot.user"],
    "source_ips": ["45.76.123.98"],
    "pattern_matched": "curl"
  }
}
```

**Triage Recommendation:**
1. Verify if `api.bot.user` is legitimate automation
2. If unauthorized, revoke API credentials
3. Add IP to allowlist if legitimate monitoring tool
4. Review API logs for data exfiltration

---

### Scenario 5: API Abuse

**Objective:** Demonstrate detection of rate spikes

**Attack Details:**
- Source IP: `45.76.123.98`
- User: `scraper.account`
- Request count: 150 in 3 minutes
- Rate: ~30 requests/second

**Expected Alert:**
```json
{
  "rule_id": "api_abuse",
  "severity": "medium",
  "summary": "API abuse detected: 150 requests from 45.76.123.98 in 5 minutes",
  "evidence": {
    "source_ip": "45.76.123.98",
    "request_count": 150,
    "unique_actions": 3,
    "requests_per_second": 30
  }
}
```

**Triage Recommendation:**
1. Implement rate limiting (e.g., 10 req/sec)
2. Block IP if malicious scraping
3. Contact customer if legitimate high-volume user
4. Add to allowlist if authorized bulk processing

---

### Scenario 6: Privilege Escalation

**Objective:** Demonstrate detection of IAM changes

**Attack Details:**
- Actor: `admin.user`
- Actions:
  1. Create new admin role
  2. Attach admin policy to role
  3. Add regular user to admin group
- Time: 5-minute window

**Expected Alerts:** 3 (one per action)

**Example Alert:**
```json
{
  "rule_id": "privilege_escalation",
  "severity": "critical",
  "summary": "Privilege escalation detected: admin.user performed iam.role.attach_policy on super-admin-role",
  "evidence": {
    "actor": "admin.user",
    "action": "iam.role.attach_policy",
    "resource": "super-admin-role",
    "outcome": "success",
    "source_ip": "192.168.1.10",
    "timestamp": "2024-02-09T20:17:00Z"
  }
}
```

**Triage Recommendation:**
1. Verify with `admin.user` if authorized change
2. Check change management system for ticket
3. Review new role permissions for excessive privilege
4. Audit recent actions by promoted user

---

## Running Demo Scenarios

### Step 1: Generate Logs

```bash
cd signalforge
python examples/generators/generate_demo_logs.py
```

This creates `examples/sample_logs/demo_logs.jsonl` with ~1000 events.

### Step 2: Start Services

```bash
# Terminal 1: Backend
uvicorn backend.app.main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```

### Step 3: Ingest Demo Logs

```bash
# Ingest all events
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @examples/sample_logs/demo_logs.jsonl
```

### Step 4: Run Detections

```bash
curl -X POST http://localhost:8000/api/v1/detections/run
```

Expected output:
```json
{
  "alerts_generated": 8,
  "rules_executed": [
    "brute_force_login",
    "password_spray",
    "impossible_travel",
    "suspicious_user_agent",
    "api_abuse",
    "privilege_escalation"
  ],
  "execution_time_ms": 245.3
}
```

### Step 5: View Alerts in UI

Navigate to http://localhost:3000

You should see:
- 8+ alerts across different severities
- Filters by status and severity working
- Click any alert to view detailed evidence
- Triage actions functional

---

## Custom Demo Scenarios

### Creating Your Own Scenarios

```python
# examples/generators/custom_scenario.py

from datetime import datetime, timedelta, timezone
import json

def generate_custom_attack():
    start_time = datetime.now(timezone.utc)
    events = []
    
    # Your attack logic here
    for i in range(10):
        event = {
            "timestamp": (start_time + timedelta(seconds=i*10)).isoformat(),
            "actor": "target_user",
            "source.ip": "attacker_ip",
            "action": "user.login",
            "outcome": "failure",
        }
        events.append(event)
    
    # Write to file
    with open("custom_attack.jsonl", "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    generate_custom_attack()
```

---

## Expected Triage Workflow

### Typical SOC Analyst Flow

1. **Alert Notification**: Analyst sees new alert on dashboard
2. **Initial Triage**: Review severity and summary
3. **Evidence Review**: Click alert to view detailed evidence
4. **Investigation**: 
   - Check threat intelligence for IP
   - Verify with user if needed
   - Review related events
5. **Action**:
   - Mark as triaged while investigating
   - If false positive, mark with reason
   - If real threat, escalate and block
   - If benign, close alert
6. **Resolution**: Update alert status to closed

### Metrics to Track

- **MTTD (Mean Time To Detect)**: Time from attack start to alert
- **MTTR (Mean Time To Respond)**: Time from alert to triage
- **False Positive Rate**: FP alerts / total alerts
- **Coverage**: % of attacks detected

---

## Troubleshooting

### No Alerts Generated

**Check:**
1. Events were ingested: `curl http://localhost:8000/api/v1/alerts`
2. Detection ran successfully (check execution_time_ms > 0)
3. Time windows overlap with ingested events
4. No allowlist entries suppressing alerts

**Solution:**
```bash
# Check database has events
sqlite3 signalforge.db "SELECT COUNT(*) FROM events;"

# Re-run detection
curl -X POST http://localhost:8000/api/v1/detections/run
```

### Excessive Alerts

**Cause:** Normal activity triggering detection rules

**Solution:**
1. Tune thresholds in rule files
2. Add known-safe IPs to allowlist
3. Adjust time windows

### Missing Expected Alert

**Cause:** Events outside detection window or below threshold

**Solution:**
1. Check event timestamps vs. current time
2. Verify threshold met (e.g., brute force needs 5+ failures)
3. Manually trigger detection immediately after ingestion
