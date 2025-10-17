🏪 Multi-Branch Inventory Management System with Blockchain ⛓️
🔐 Technologies Used

Python 3.8+

Tkinter (GUI)

MySQL (Database)

Blockchain for Secure Transaction Logging

Hashlib, JSON, Time, Datetime

📖 Overview

This project is a multi-branch inventory management system integrated with a blockchain ledger for transparent and tamper-proof transaction records.
Each branch (like Inventory_1, Inventory_2) maintains its own blockchain to record Add/Update/Delete operations on products.

The system includes:

✅ Secure multi-user login per branch

✅ Real-time inventory management (Add, Update, Delete)

✅ Blockchain ledger for every action

✅ Search and filter (both local and DB search)

✅ GUI interface built using Tkinter

📂 Project Structure
├── inventory_app.py        # Main program file (GUI + blockchain + DB integration)
├── README.md               # Project documentation
└── inventory_db.sql        # SQL script to create required tables (you’ll create this)

⚙️ Setup Instructions
1️⃣ Prerequisites

Make sure the following are installed:

Python 3.8+

MySQL Server

MySQL Connector for Python
Install it via pip:

pip install mysql-connector-python

2️⃣ Database Setup

Create a database named inventory_db in MySQL:

CREATE DATABASE inventory_db;
USE inventory_db;


Then, create the required tables:

-- Table for blockchain data
CREATE TABLE blockchain (
    block_index INT PRIMARY KEY,
    timestamp DATETIME,
    nonce INT,
    previous_hash VARCHAR(255),
    branch VARCHAR(50)
);

-- Table for transactions stored in blockchain
CREATE TABLE transactions (
    block_index INT,
    user VARCHAR(50),
    action VARCHAR(50),
    item VARCHAR(100),
    quantity INT,
    timestamp DATETIME,
    branch VARCHAR(50)
);

-- Table for inventory items
CREATE TABLE inventory (
    item VARCHAR(100),
    quantity INT,
    branch VARCHAR(50),
    PRIMARY KEY (item, branch)
);

-- Table for user credentials
CREATE TABLE users (
    username VARCHAR(50) PRIMARY KEY,
    pin VARCHAR(10),
    branch VARCHAR(50)
);


Now insert some sample users:

INSERT INTO users (username, pin, branch) VALUES
('admin1', '1234', 'Inventory_1'),
('user1', '1111', 'Inventory_1'),
('manager1', '5678', 'Inventory_1'),
('admin2', '4321', 'Inventory_2'),
('user2', '2222', 'Inventory_2'),
('manager2', '8765', 'Inventory_2');

3️⃣ Run the Application

Run the main file:

python inventory_app.py

💻 How It Works
🪟 Login Screen

Choose a branch (Inventory_1 or Inventory_2)

Enter user credentials (e.g., admin1 / 1234)

Logs into that branch’s inventory dashboard.

📦 Inventory Management

Add new items or update quantities.

Delete items.

View or search inventory in real-time.

🔍 Search Features

Live Filter: Filters visible items as you type.

DB Search: Fetches matching results directly from the database using SQL LIKE.

⛓️ Blockchain Ledger

Every transaction (Add, Update, Delete) is:

Added as a transaction in a block.

Secured using Proof of Work.

Stored permanently in MySQL.

Viewable via “View Blockchain” button.

🧠 Blockchain Implementation

Each branch has an independent blockchain.
Every new block:

Stores all pending transactions.

Includes a unique nonce via Proof of Work.

Is hashed using SHA256.

Is appended to the branch’s blockchain table.

📸 App Preview (Conceptual)
Screen	Description
🔑 Login Page	Select branch and enter credentials
📋 Inventory Dashboard	View and manage items
🔎 Search Bar	Filter or search items
⛓️ Blockchain Viewer	Inspect secure ledger
🚀 Features Summary
Feature	Description
🔐 Multi-User Login	Separate users per branch
🏢 Multi-Branch Support	Each branch has its own ledger
📊 Inventory Control	Add, update, and delete stock
⛓️ Blockchain Security	Tamper-proof transaction storage
🔍 Dual Search Modes	Local filter + DB search
🖥️ GUI Interface	Built using Tkinter
🧾 Sample Login Credentials
Branch	Username	PIN
Inventory_1	admin1	1234
Inventory_1	user1	1111
Inventory_1	manager1	5678
Inventory_2	admin2	4321
Inventory_2	user2	2222
Inventory_2	manager2	8765
🧰 Dependencies
Library	Installation Command
mysql-connector-python	pip install mysql-connector-python
tkinter	(Included by default with Python)
🧑‍💻 Developer Notes

Ensure MySQL service is running before launching the app.

If you modify table structures, update queries in the code accordingly.

Blockchain validation can be extended by using is_chain_valid() before showing blockchain records.

🏁 Future Enhancements

Add role-based permissions (Admin, Manager, User)

Support for exporting blockchain ledger as CSV/PDF

REST API for mobile integration

Multi-threaded mining simulation

Integration with cloud-hosted databases

🧑‍🎓 Author

Chandan Hegde
📘 B.E. 4th Semester – Design and Analysis of Algorithms
🗓️ Project: Blockchain-based Inventory System (2025)
