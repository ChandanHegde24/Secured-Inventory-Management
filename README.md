# 🛡️ Multi-Branch Inventory System with Blockchain Ledger

A robust, high-performance inventory management application built with Python (Tkinter) and MySQL. This v2.0 release features a secure, immutable blockchain audit log for all transactions, Role-Based Access Control (RBAC), and a fully multi-threaded, non-blocking UI.

-----

### Application Dashboard

**Login Page:**
<img width="1920" height="1080" alt="Screenshot (31)" src="https://github.com/user-attachments/assets/7628eb67-1623-476c-9edb-6a468bba23f2" />
**Inventory Home:**
<img width="1920" height="1080" alt="Screenshot (29)" src="https://github.com/user-attachments/assets/2b1b13ee-bd46-41f8-8384-01aecec596f3" />
**Blockchain Ledger:**
<img width="1920" height="1080" alt="Screenshot (30)" src="https://github.com/user-attachments/assets/db99580e-3fff-49e2-bcbf-fee8fb17c5f2" />

-----

## 🚀 Key Features (v2.0)

  * **⛓️ Immutable Blockchain Ledger:** All inventory changes (adds, transfers, deletes) are recorded as transactions in a tamper-detectable blockchain.
  * **👤 Role-Based Access Control (RBAC):** Secure user (`user`) and administrator (`admin`) roles. Admins have exclusive access to view the global blockchain ledger.
  * **⚡ High-Performance UI:** The entire application is multi-threaded. No database operation *ever* freezes the UI, ensuring a smooth, responsive user experience.
  * **📈 Scalable By Design:** The blockchain now uses header-only loading, meaning the app starts instantly and uses minimal RAM, even with millions of transactions.
  * **🔐 Secure Credentials:** All user PINs are hashed using **bcrypt**, the industry-standard.
  * **📦 Atomic Transactions:** Stock transfers are fully atomic (using `FOR UPDATE` and single commits). If a transfer fails, the entire transaction is rolled back, preventing data corruption.
  * **🏪 Multi-Branch Support:** Manage inventory and conduct seamless stock transfers between multiple branches.

-----

## 💻 Tech Stack

  * **Core:** Python 3
  * **GUI:** Tkinter (standard library)
  * **Database:** MySQL Server
  * **Connector:** `mysql-connector-python`
  * **Security:** `bcrypt`
  * **Config:** `python-dotenv`

-----

## ⚙️ Setup & Installation

Follow these steps to get the application running locally.

### 1\. Clone the Repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2\. Install Dependencies

This project requires a few external Python libraries.

```bash
pip install mysql-connector-python bcrypt python-dotenv
```

### 3\. Set Up the MySQL Database

You must have a running MySQL server.

1.  Log in to your MySQL server and create the database:

    ```sql
    CREATE DATABASE inventory_db;
    ```

2.  Create a dedicated user for the app (Recommended for security):

    ```sql
    -- Creates a user 'inventory_app_user' with the password '123@cn'
    CREATE USER 'inventory_app_user'@'localhost' IDENTIFIED BY '123@cn';
    GRANT ALL PRIVILEGES ON inventory_db.* TO 'inventory_app_user'@'localhost';
    FLUSH PRIVILEGES;
    ```

    *(You can change the username and password, just make sure to update your `.env` file.)*

3.  Run the following SQL in your `inventory_db` to create all necessary tables:

    ```sql
    -- 1. 'users' table (stores login info and roles)
    CREATE TABLE users (
        username VARCHAR(50) PRIMARY KEY NOT NULL,
        pin VARCHAR(60) NOT NULL, -- Increased to 60 for bcrypt
        branch VARCHAR(50) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user' -- The new RBAC column
    );

    -- 2. 'inventory' table (stores current stock)
    CREATE TABLE inventory (
        item VARCHAR(255) NOT NULL,
        quantity INT NOT NULL,
        branch VARCHAR(50) NOT NULL,
        PRIMARY KEY (item, branch) -- Composite key
    );

    -- 3. 'blockchain' table (stores block headers)
    CREATE TABLE blockchain (
        block_index INT PRIMARY KEY NOT NULL,
        timestamp DATETIME NOT NULL,
        nonce INT NOT NULL,
        previous_hash VARCHAR(64) NOT NULL
    );

    -- 4. 'transactions' table (stores all transaction data)
    CREATE TABLE transactions (
        tx_id INT AUTO_INCREMENT PRIMARY KEY,
        block_index INT NOT NULL,
        user VARCHAR(50),
        action VARCHAR(50),
        item VARCHAR(255),
        quantity INT,
        timestamp DATETIME,
        branch VARCHAR(50),
        FOREIGN KEY (block_index) REFERENCES blockchain(block_index)
    );
    ```

### 4\. Create your `.env` File

In the root of the project, create a file named `.env`. This securely stores your database credentials so they aren't hard-coded in the script.

```ini
# .env file
DB_HOST=localhost
DB_USER=inventory_app_user
DB_PASS=123@cn
DB_NAME=inventory_db
```

### 5\. Create Sample Users & Hash PINs

**This is a critical two-step process.**

1.  **Insert Users with Plaintext PINs:**
    First, add your sample users to the `users` table. Use **plaintext (regular) PINs** for this one-time setup.

    ```sql
    -- Example:
    INSERT INTO users (username, pin, branch, role)
    VALUES
    ('admin1', '1234', 'Inventory_1', 'admin'),
    ('user1', '0000', 'Inventory_1', 'user'),
    ('admin2', '5678', 'Inventory_2', 'admin');
    ```

2.  **Run the Migration Script:**
    Now, run the `migrate_pins.py` script from your terminal. This will find all plaintext PINs, securely hash them with bcrypt, and update the database.

    ```bash
    python migrate_pins.py
    ```

### 6\. Run the Application\!

You're all set. Launch the app:

```bash
python inventory_app.py
```

You can now log in using the credentials you created (e.g., `admin1` / `1234`).

-----

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
