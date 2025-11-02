# Secured Inventory Management

Secure, minimal, and extensible Python-based Inventory Management designed
for small teams and personal projects — with security-first defaults.

Table of Contents
- Project overview
- Key features
- Quick start
- Configuration
- Usage examples
- Security considerations
- Testing
- Contributing
- License

Project overview
----------------
Secured Inventory Management is a compact Python application that provides:
- Secure user authentication and role-based access control.
- CRUD operations for inventory items (create, read, update, delete).
- Audit logging for critical actions.
- Simple persistence (file-based or lightweight DB adapter).
- Extensible structure to plug in real DBs, cloud storage, or a web UI.

This repository focuses on delivering an auditable, secure foundation so you
can extend to your environment (desktop, server, or cloud).

Key features
------------
- Authentication & Authorization
  - Password hashing (bcrypt or Argon2 where available).
  - Roles (admin, manager, viewer) with permission checks.
- Inventory management
  - Items with metadata: SKU, name, quantity, location, supplier, tags.
  - Stock adjustments with reason/notes.
- Audit trail
  - Immutable append-only audit log for sensitive operations.
- Configurable storage
  - Default file-based storage, adapters for SQLite/Postgres possible.
- CLI-first UX
  - Small command-line tool for portability and automation.
- Tests
  - Unit tests for core logic and security checks.

Quick start (development)
-------------------------
Prerequisites:
- Python 3.10+ recommended
- pip

1. Clone
   git clone https://github.com/ChandanHegde24/Secured-Inventory-Management.git
   cd Secured-Inventory-Management

2. Create & activate virtualenv
   python -m venv .venv
   source .venv/bin/activate   # Unix / macOS
   .venv\Scripts\activate      # Windows PowerShell

3. Install dependencies
   pip install -r requirements.txt

4. Initialize storage & create admin
   python -m sim.init --create-admin

5. Run (CLI)
   python -m sim.cli --help

Replace `sim` with the actual package/module name if different — see the package top-level module.

Configuration
-------------
Configuration is driven by:
- config.yaml (in repo root or $SIM_CONFIG)
- environment variables (for secrets/DB URLs)

Important configuration keys:
- storage.type: file | sqlite | postgres
- storage.path: path for file storage or sqlite file
- auth.password_policy: min_length, require_digits, require_special
- logging.audit_path: path to audit log

Example config.yaml:
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

Usage examples
--------------
Create an item:
```bash
python -m sim.cli add-item \
  --sku "SKU-001" --name "Widget" --quantity 10 --location "A1" \
  --supplier "Acme Co." --tags "blue,small"
```

Update stock (adds audit entry):
```bash
python -m sim.cli adjust-stock --sku "SKU-001" --delta -2 --reason "sold 2 units"
```

List items:
```bash
python -m sim.cli list-items --format table
```

Create a user (admin only):
```bash
python -m sim.cli create-user --username alice --role manager
```

Security considerations
-----------------------
This project is built with security in mind, but your deployment must follow best practices:
- Never store plaintext secrets in repository. Use environment variables or secret stores.
- Use a secure password hasher:
  - Argon2 is preferred; fall back to bcrypt with sufficiently high rounds.
- Protect the audit log:
  - Keep audit files append-only and backed up.
  - Consider remote storage (WORM / immutable) for compliance.
- Use TLS on any network-exposed services.
- Keep dependencies up to date and run vulnerability scans.

Testing
-------
Run unit tests:
```bash
pytest -q
```

To run a single test module:
```bash
pytest tests/test_inventory.py -q
```

CI
--
A GitHub Actions workflow (if present) runs linting and tests on push and PRs.
Ensure your branch follows the workflow naming conventions when creating feature branches.

Project layout (high level)
---------------------------
- sim/                 # main package (core logic, auth, storage adapters)
  - cli.py             # command line entrypoints
  - auth.py            # authentication & role checks
  - storage.py         # abstract storage + file/sqlite adapters
  - inventory.py       # business logic for items & stock adjustments
  - audit.py           # audit logging helpers
- tests/               # pytest test suite
- config.yaml          # example config
- requirements.txt
- README.md

Maintainers
-----------
- ChandanHegde24 (owner)

License
-------
This project is provided under the MIT License. See LICENSE for details.

Acknowledgements
----------------
Built with security-first design patterns, open-source libraries, and community best practices.
