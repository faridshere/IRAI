# IRAI — Security AI Assistant

A clean, dark-themed AI chat application for Security Operations professionals.
Powered by OpenAI GPT-4o with specialized modes for:

- **Cortex XDR** — XQL queries, BIOC rules, incident response, threat hunting
- **QRadar SIEM** — AQL queries, correlation rules, DSM configuration, offense investigation
- **Sigma Rules** — Write, convert, and validate Sigma detection rules
- **General Security** — SOC operations, MITRE ATT&CK, threat intelligence

Features image upload for screenshot analysis (e.g., paste alert screenshots for AI triage).

## Quick Start

```bash
# 1. Clone and install
npm install

# 2. Configure your OpenAI API key
cp .env.example .env
# Edit .env and set OPENAI_API_KEY=sk-...

# 3. Run
npm start
# Open http://localhost:3000
```

## Requirements

- Node.js ≥ 18
- OpenAI API key (GPT-4o access recommended)
