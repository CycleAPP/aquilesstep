# Aquiles

⚔️ **AI-Assisted Pentesting Orchestrator** ⚔️

Aquiles is an intelligent, automated, and policy-driven penetration testing framework designed to streamline and orchestrate the execution of security tools. It acts as a "Red Team orchestrator", seamlessly connecting tools like `nmap`, `nuclei`, `ffuf`, `searchsploit`, and many others into a smart pipeline.

With an embedded AI engine (supporting DeepSeek and OpenAI), Aquiles builds contextual assessment plans, parses stdout outputs, handles errors intelligently (retries and fallbacks), and provides actionable summaries without the noise.

## Features
- **AI-Assisted Planning**: Feeds your assessment scope and previous tool findings to an LLM to generate adaptive attack plans.
- **Strict Policy Engine**: Prevents running disruptive tools against unauthorized targets.
- **Auto-Recovery**: Recovers gracefully from tool crashes, timeouts, and network issues.
- **YAML Tool Catalog**: Infinitely extensible. Want to add a custom script? Just add a new YAML definition to `catalog/tools/`.
- **Intrusive Exploit Scanning**: Automatically correlates Nmap results with `searchsploit` for zero-day/CVE discovery, and runs aggressive `nuclei` templates.
- **Persistent Sessions**: Disconnected? `aquiles resume` picks up exactly where it left off.

---

## 🚀 Installation

Aquiles runs best on a penetration testing distribution like **Kali Linux** or **Parrot OS**, as it relies heavily on native security binaries.

Clone the repository and run the setup script:

```bash
git clone https://github.com/CycleAPP/aquilesstep.git
cd aquilesstep
chmod +x install.sh
./install.sh
```

*(The `install.sh` script will install essential tools via `apt` and set up a Python virtual environment with all required libraries).*

---

## ⚙️ Configuration (AI Mode)

To enable the AI planning and analysis features (Highly Recommended), you need an API key. Aquiles supports both **DeepSeek** and **OpenAI**.

Export your key in your terminal:

```bash
# For DeepSeek (Recommended for coding/pentest reasoning)
export DEEPSEEK_API_KEY="sk-your-deepseek-key"

# OR for OpenAI (GPT-4)
export OPENAI_API_KEY="sk-your-openai-key"
```

*If no key is provided, Aquiles will gracefully fall back to executing standard predefined assessment templates without AI analysis.*

---

## 🎯 Usage

To launch the interactive assessment wizard:

```bash
# Make sure your virtual environment is active
source venv/bin/activate

# Start Aquiles
./aquiles.sh start
```

### The Assessment Flow
1. **Assessment Type**: Choose between Web App, Internal Infra, Active Directory, API, etc.
2. **Scope Definition**: Define the authorized domains and IPs.
3. **Execution**: Aquiles will run through phases (Recon -> Enum -> Path Discovery -> Vuln Scanning).
4. **Hint System**: Between phases, you can type hints (e.g., `focus on port 80` or `skip dnsenum`) to steer the AI's internal logic.

### Resuming Sessions
If a scan takes too long or gets interrupted, find the session ID and resume:
```bash
# List all previous sessions
./aquiles.sh sessions

# Resume a specific session
./aquiles.sh resume aquiles_session_2024...
```

---

## 📂 Customizing Tools
Add your tools in `aquiles/catalog/tools/` using a simple YAML definition mapping the tool's execution strings to our standardized targets (`{target}`, `{output_file}`). Aquiles parses it automatically!

---
*Created for Red Teamers. Always ensure you have explicit written permission before scanning any target.*
