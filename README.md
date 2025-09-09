# Secured Inventory Management System

A secure, blockchain-based inventory management system with multi-branch support and a GUI built using Tkinter. All inventory changes and actions are timestamped, recorded, and auditable on a blockchain-like ledger stored in a MySQL database.

---

## Features

- **User Authentication**: PIN-based login for authorized access.
- **Blockchain Ledger**: Every inventory transaction is stored as a block, ensuring immutability and auditability.
- **Multi-Branch Inventory**: Manage and update stock for multiple items securely.
- **GUI Application**: Easy-to-use interface built with Tkinter.
- **MySQL Database**: Stores users, inventory, transactions, and blockchain records.

---

## Requirements

- Python 3.x
- MySQL Server
- Python packages:
  - `mysql-connector-python`
  - `tkinter` (usually included with Python)
  - `ttk` (comes with tkinter)
- MySQL database with the following tables:

### Example Table Schemas

```sql
CREATE DATABASE inventory_db;

USE inventory_db;

CREATE TABLE users (
    username VARCHAR(255) PRIMARY KEY,
    pin VARCHAR(255) NOT NULL
);

CREATE TABLE inventory (
    item VARCHAR(255) PRIMARY KEY,
    quantity INT NOT NULL
);

CREATE TABLE blockchain (
    block_index INT PRIMARY KEY AUTO_INCREMENT,
    timestamp DATETIME NOT NULL,
    nonce INT NOT NULL,
    previous_hash VARCHAR(255) NOT NULL
);

CREATE TABLE transactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    block_index INT,
    user VARCHAR(255),
    action VARCHAR(255),
    item VARCHAR(255),
    quantity INT,
    timestamp DATETIME,
    FOREIGN KEY (block_index) REFERENCES blockchain(block_index)
);
```

---

## Setup Instructions

1. **Clone the repository**:

    ```sh
    git clone https://github.com/ChandanHegde24/Secured-Inventory-Management.git
    cd Secured-Inventory-Management
    ```

2. **Install dependencies**:

    ```sh
    pip install mysql-connector-python
    ```

3. **Configure MySQL**:

    - Update the MySQL connection details in the Python script (host, user, password, database) as needed.
    - Ensure your MySQL server is running and accessible.
    - Create the database and tables using the SQL schema above.

4. **Add Users**:

    Insert at least one user into the `users` table:

    ```sql
    INSERT INTO users (username, pin) VALUES ('admin', '1234');
    ```

5. **Run the Application**:

    ```sh
    python <your_script_name>.py
    ```

---

## Usage

- **Login** using your username and pin.
- **View and update inventory** items and quantities.
- **Add/Update Stock**: Enter item name and quantity to update inventory.
- **View Blockchain**: See the full ledger of all actions performed.
- **Logout**: Log out and return to the login screen.

---

## Security and Integrity

- Every transaction is appended to the blockchain, which uses proof-of-work and hashing to guarantee data integrity.
- All actions are timestamped.
- The blockchain can be reviewed within the application for full transparency.

---

## Screenshots

*(Add screenshots of the login screen, inventory list, and blockchain viewer if possible.)*

---

## License

This project is for educational purposes. See [LICENSE](LICENSE) for more details.

---

## Author

Chandan Hegde ([@ChandanHegde24](https://github.com/ChandanHegde24))

---
```
