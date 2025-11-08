# Secured Inventory Management

Secure, minimal, and extensible Python-based Inventory Management designed
for small teams and personal projects — with security-first defaults.

---

## 📋 Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Quick Start](#quick-start-development)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)
- [Testing](#testing)

---

## 🚀 Project Overview
Secured Inventory Management is a compact Python application that provides:
- 🔒 Secure user authentication and role-based access control
- 📦 CRUD operations for inventory items
- 📝 Audit logging for critical actions
- 💾 Simple persistence (file-based or lightweight DB adapter)
- 🧩 Extensible structure for real DBs, cloud storage, or a web UI

> **Focus:** Delivering an auditable, secure foundation you can extend for desktop, server, or cloud usage.

---

## 🌟 Key Features
- **Authentication & Authorization**
  - Secure password hashing (bcrypt/Argon2)
  - Role-based permissions *(admin, manager, viewer)*
- **Inventory Management**
  - Item metadata: SKU, name, quantity, location, supplier, tags
  - Stock adjustments with reasons/notes
- **Audit Trail**
  - Immutable, append-only audit log
- **Configurable Storage**
  - File-based by default, adapters for SQLite/Postgres possible
- **CLI-first Experience**
  - Portable, automation-friendly command-line tool
- **Robust Testing**
  - Unit tests for core logic and security

---

## ⚡ Quick Start (Development)
**Prerequisites:**  
- Python 3.10+  
- `pip`

```bash
# 1. Clone the repo
git clone https://github.com/ChandanHegde24/Secured-Inventory-Management.git
cd Secured-Inventory-Management

# 2. Set up virtual environment
python -m venv .venv
source .venv/bin/activate   # Unix/macOS
.venv\Scripts\activate      # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize storage & create admin
python -m sim.init --create-admin

# 5. Run the CLI
python -m sim.cli --help
```
*Replace `sim` with your actual package/module name if different.*

---

## ⚙️ Configuration

Driven by:
- `config.yaml` (in repo root or `$SIM_CONFIG`)
- Environment variables (secrets/DB URLs)

**Example `config.yaml`:**
```yaml
storage:
  type: file
  path: data/storage.json

auth:
  bcrypt_rounds: 12
  default_role: viewer

logging:
  audit_path: data/audit.log
```

---

## 🛠️ Usage Examples

**Add an item:**
```bash
python -m sim.cli add-item \
  --sku "SKU-001" --name "Widget" --quantity 10 --location "A1" \
  --supplier "Acme Co." --tags "blue,small"
```

**Adjust stock (audited):**
```bash
python -m sim.cli adjust-stock --sku "SKU-001" --delta -2 --reason "sold 2 units"
```

**List items:**
```bash
python -m sim.cli list-items --format table
```

**Create a user (admin only):**
```bash
# (See CLI help for details)
```

---

## 🛡️ Security Considerations

- Strong password policy (configurable)
- Encrypted secrets in config
- Audit logs for every sensitive action

---

## 🧪 Testing

- Run unit tests with:
```bash
pytest
---
