# IRAI — Security AI Assistant

A clean, dark-themed AI chat application for Security Operations professionals.
Powered by OpenAI GPT-4o with specialised modes for:

- **⚡ Cortex XDR** — XQL queries, BIOC rules, incident response, threat hunting
- **📡 QRadar SIEM** — AQL queries, correlation rules, DSM config, offense investigation
- **Σ Sigma Rules** — Write, convert and validate Sigma detection rules
- **🔍 General Security** — SOC operations, MITRE ATT&CK, threat intelligence

Supports image uploads — paste alert screenshots for instant AI triage.

---

## 🌐 GitHub Pages (Recommended)

The site is deployed automatically from the `docs/` folder via GitHub Actions.

### First-time setup

1. **Enable GitHub Pages** in your repo:
   - Go to **Settings → Pages**
   - Set Source to **"GitHub Actions"**

2. Push to `main` — the workflow in `.github/workflows/deploy-pages.yml` deploys automatically.

3. Open the published URL and click **API Settings** in the bottom-left to enter your OpenAI API key.
   - Your key is stored **only in your browser's localStorage** — it never leaves your device.
   - Get a key at [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

---

## 💻 Local Development (with Node.js server)

```bash
# 1. Install dependencies
npm install

# 2. Configure your OpenAI API key
cp .env.example .env
# Edit .env and set OPENAI_API_KEY=sk-...

# 3. Run
npm start
# Open http://localhost:3000
```

The local server proxies API calls through the backend so the key stays server-side.

---

## Requirements

- Node.js ≥ 18 (local dev only)
- OpenAI API key (GPT-4o access)
