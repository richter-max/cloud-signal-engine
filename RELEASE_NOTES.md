# SignalForge v0.1.0 Release Notes

**Release Date:** February 9, 2024

**Status:** Initial Public Release

---

## 🎉 Overview

SignalForge v0.1.0 marks the first public release of production-style security detection and abuse monitoring platform. This release provides a complete end-to-end system for ingesting security events, detecting threats using rule-based detection, and triaging alerts through a modern web interface.

## 🚀 What's New

### Core Features

#### Event Ingestion & Normalization
- **HTTP ingestion API** supporting both single events and batch uploads
- **JSONL format support** for streaming large log files
- **Intelligent normalization** handling diverse log formats (AWS CloudTrail, Azure AD, custom)
- **Canonical event schema** with UTC timestamps, source IP, actor, action, outcome, and forensic raw data

#### Detection Engine
- **6 production-ready detection rules** mapped to MITRE ATT&CK
- **Time-windowed analysis** (5-60 minute windows per rule)
- **Evidence collection** with full forensic context (IPs, timestamps, event IDs)
- **Manual and scheduled execution** (default: every 5 minutes)
- **Allowlist support** to suppress known-safe entities
- **Deduplication logic** to reduce alert fatigue

#### Alert Management
- **Comprehensive triage workflow** (open → triaged → closed → false_positive)
- **False positive tracking** with reason recording for rule tuning
- **Allowlist management** for IPs and actors with optional expiry
- **REST API** for programmatic access
- **Filtering and search** by status, severity, rule ID, and time range

#### Web Dashboard
- **Modern Next.js 14 interface** with dark theme
- **Real-time stats** showing total alerts, open alerts, critical/high counts
- **Alert list view** with severity and status badges
- **Alert detail page** with expandable evidence viewer
- **One-click triage actions** for status updates and false positive marking
- **Auto-refresh** every 30 seconds for near-real-time monitoring

### Detection Rules

All detection rules include MITRE ATT&CK mappings and detailed evidence:

1. **Brute Force Login Detection** (T1110)
   - Severity: HIGH
   - Window: 15 minutes
   - Threshold: 5+ failed attempts from same IP

2. **Password Spray Detection** (T1110.003)
   - Severity: CRITICAL
   - Window: 30 minutes
   - Threshold: 10+ unique users targeted from one IP

3. **Impossible Travel Detection** (T1078)
   - Severity: HIGH
   - Window: 60 minutes
   - Logic: Same user from distant IPs in impossible timeframe

4. **Suspicious User-Agent Detection** (T1071)
   - Severity: MEDIUM
   - Window: 15 minutes
   - Patterns: curl, wget, python-requests, empty UA

5. **API Abuse / Rate Spike Detection** (T1498)
   - Severity: MEDIUM
   - Window: 5 minutes
   - Threshold: 100+ requests per IP or user

6. **Privilege Escalation Detection** (T1078.004, T1548)
   - Severity: CRITICAL
   - Window: 60 minutes
   - Monitored: IAM role/policy/user changes

### Testing & Quality

- **Comprehensive test suite** with pytest
  - Normalization tests (timestamp parsing, field mapping)
  - Detection rule tests (all 6 rules with threshold validation)
  - API endpoint tests (ingestion, detection, alerts, allowlist)
- **GitHub Actions CI** with automated linting and test execution
- **Ruff linting** for code quality and consistency
- **80%+ test coverage** on backend code

### Documentation

- **Detailed README** with quick start, architecture diagrams, and API docs
- **Architecture Deep-Dive** (`docs/architecture.md`) covering system design and scaling
- **Detection Rules Reference** (`docs/detection_rules.md`) with tuning guidance
- **Threat Model** (`docs/threat_model.md`) documenting attack scenarios and coverage
- **Demo Scenarios** (`docs/demo_scenarios.md`) with step-by-step walkthroughs

### Demo & Examples

- **Realistic log generator** creating 1000+ events with 6 attack scenarios
- **Sample JSONL logs** for immediate testing
- **End-to-end demo flow** documented with expected results

---

## 📦 What's Included

### Backend (Python + FastAPI)
```
backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── database.py          # SQLAlchemy setup
│   ├── models.py            # Data models
│   ├── schemas.py           # Pydantic schemas
│   ├── routers/             # API endpoints
│   │   ├── ingest.py
│   │   ├── detections.py
│   │   └── alerts.py
│   └── services/            # Business logic
│       ├── normalizer.py
│       ├── detection_engine.py
│       └── rules/           # Detection rules
│           ├── brute_force.py
│           ├── password_spray.py
│           ├── impossible_travel.py
│           ├── suspicious_user_agent.py
│           ├── api_abuse.py
│           └── privilege_escalation.py
└── tests/                   # Test suite
```

### Frontend (Next.js 14 + Tailwind)
```
frontend/
├── app/
│   ├── page.tsx             # Dashboard
│   └── alerts/[id]/page.tsx # Alert detail
└── components/              # React components
    ├── alert-card.tsx
    ├── severity-badge.tsx
    ├── status-badge.tsx
    ├── evidence-viewer.tsx
    └── triage-panel.tsx
```

### Examples & Documentation
```
examples/
├── generators/
│   └── generate_demo_logs.py
└── sample_logs/
    └── demo_logs.jsonl

docs/
├── architecture.md
├── detection_rules.md
├── threat_model.md
└── demo_scenarios.md
```

---

## 🐛 Known Limitations

### MVP Constraints

1. **SQLite Storage**
   - Single-writer limitation affects concurrent ingestion throughput
   - Recommended for <100K events/day
   - Migration to PostgreSQL planned for production deployments

2. **Impossible Travel Heuristic**
   - Uses IP prefix-based distance estimation
   - Not as accurate as GeoIP database
   - GeoIP2 integration planned for v0.2.0

3. **No Real-Time Streaming**
   - Detection runs on 5-minute schedule
   - UI polling every 30 seconds
   - WebSocket support planned for v0.2.0

4. **Basic Deduplication**
   - Simple time-based suppression (1-hour window)
   - No evidence fingerprinting
   - Enhanced dedup logic planned

5. **No Authentication**
   - API endpoints are unauthenticated (internal deployment assumption)
   - JWT authentication planned for multi-tenant deployments

### False Positive Potential

- **Password Spray**: Legitimate SSO gateways may trigger
  - Mitigation: Add to allowlist
- **API Abuse**: Batch processing jobs may spike
  - Mitigation: Adjust threshold or allowlist service accounts
- **Privilege Escalation**: All IAM changes trigger alerts
  - Mitigation: High false positive rate expected, tuning needed

---

## 🔧 Deployment Requirements

### Minimum Requirements
- **Python**: 3.11+
- **Node.js**: 20+
- **RAM**: 1GB
- **Disk**: 5GB (for database growth)

### Recommended for Production
- **Database**: PostgreSQL 14+
- **RAM**: 4GB+
- **CPU**: 2+ cores
- **Deployment**: Docker + Kubernetes
- **Monitoring**: Prometheus + Grafana

---

## 📚 Getting Started

### Quick Start

```bash
# 1. Install dependencies
pip install -e ".[dev]"
cd frontend && npm install

# 2. Start backend
uvicorn backend.app.main:app --reload

# 3. Start frontend (new terminal)
cd frontend && npm run dev

# 4. Generate demo data
python examples/generators/generate_demo_logs.py

# 5. Ingest and detect
curl -X POST http://localhost:8000/api/v1/ingest --data-binary @examples/sample_logs/demo_logs.jsonl
curl -X POST http://localhost:8000/api/v1/detections/run

# 6. View dashboard
# Open http://localhost:3000
```

Full documentation: https://github.com/yourusername/signalforge

---

## 🗺️ Roadmap to v0.2.0

### Planned Features

- [ ] **Machine Learning Detection**
  - Behavioral anomaly detection (LSTM)
  - Per-user baseline modeling
  - Outlier detection algorithms

- [ ] **Enhanced Integrations**
  - SIEM exports (Splunk, Elastic)
  - Threat intelligence feeds (AlienVault OTX, abuse.ch)
  - MaxMind GeoIP2 for accurate geolocation

- [ ] **Scalability Improvements**
  - PostgreSQL support with migrations
  - Horizontal scaling (load-balanced API servers)
  - Redis caching for performance
  - WebSocket real-time alerts

- [ ] **Advanced Features**
  - Alert correlation engine (multi-stage attack detection)
  - Custom rule builder UI
  - Jupyter notebook integration for investigations
  - SOAR integration (TheHive, Cortex)

- [ ] **Production Hardening**
  - JWT authentication + RBAC
  - Audit logging for compliance
  - Encryption at rest
  - Rate limiting on ingestion

### Timeline
- **v0.2.0**: Q2 2024 (ML detection, PostgreSQL, GeoIP2)
- **v0.3.0**: Q3 2024 (Multi-tenancy, SOAR, advanced correlation)

---

## 🤝 Contributing

We welcome contributions! Areas of interest:

- **New Detection Rules**: Implement additional MITRE ATT&CK techniques
- **ML Models**: Contribute anomaly detection algorithms
- **Integrations**: Add connectors for popular SIEMs and threat intel feeds
- **Performance**: Optimize query performance and database indexing
- **Documentation**: Improve guides, add tutorials, translate docs

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🙏 Credits

SignalForge is built with:

- [FastAPI](https://fastapi.tiangolo.com/) - High-performance Python web framework
- [Next.js](https://nextjs.org/) - React framework with server components
- [SQLAlchemy](https://www.sqlalchemy.org/) - Python SQL toolkit and ORM
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework
- [Pydantic](https://docs.pydantic.dev/) - Data validation using Python type annotations

Special thanks to the security research community for threat intelligence and MITRE ATT&CK framework.

---

## 📄 License

SignalForge is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## 📞 Support

- **Issues**: https://github.com/yourusername/signalforge/issues
- **Discussions**: https://github.com/yourusername/signalforge/discussions
- **Email**: security@signalforge.dev

---

**Built for Security Engineers, by Security Engineers.**

Detect threats before they become breaches.
