# Secured Inventory Management System

This project is a decentralized inventory management application that leverages blockchain technology to provide a secure, transparent, and immutable ledger for tracking inventory items.

## 🚀 Features

- **Decentralized Ledger**: All inventory transactions are recorded on a distributed blockchain, ensuring data integrity and preventing unauthorized modifications.
- **Secure & Immutable**: Cryptographic principles of the blockchain protect the inventory records from tampering.
- **Real-time Tracking**: Provides a continuously updated view of the inventory.
- **Web Interface**: A simple and intuitive web interface for users to interact with the inventory system.
- **Transaction History**: View the complete history of any inventory item, from its creation to its latest update.

## 🏛️ Architecture

The application is built with the following components:

-   **Frontend/Application Logic (`inventory_app.py`)**: A web application built with **Streamlit** that provides the user interface for managing inventory. Users can add new items, view the current inventory, and see the transaction history.
-   **Blockchain Logic (`blockchain.py`)**: A custom Python implementation of a blockchain. It handles the creation of blocks, validation of the chain (proof-of-work), and management of transactions. Each inventory change is stored as a transaction in a block.
-   **Environment Configuration (`.env`, `check_env.py`)**: The application uses a `.env` file to manage configuration variables, such as the connection to a Pinata (IPFS) account for off-chain data storage. `check_env.py` verifies that the environment is set up correctly.
-   **Data Migration (`migrate_pins.py`)**: A utility script likely used for managing data pinned to the IPFS network via Pinata, possibly for migrating or updating stored data hashes.

## ⚙️ Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Secured-Inventory-Management.git
    cd Secured-Inventory-Management
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
    ```

3.  **Install the required dependencies:**
    *(Assuming a `requirements.txt` file exists or needs to be created)*
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up the environment variables:**
    Create a file named `.env` in the root directory and add the necessary configuration, such as your Pinata API keys.
    ```
    PINATA_API_KEY="YOUR_PINATA_API_KEY"
    PINATA_SECRET_API_KEY="YOUR_PINATA_SECRET_API_KEY"
    ```

## ▶️ Usage

1.  **Run the application:**
    ```bash
    streamlit run inventory_app.py
    ```

2.  **Access the web interface:**
    Open your web browser and navigate to the local URL provided by Streamlit (usually `http://localhost:8501`).

3.  **Interact with the inventory:**
    - Use the "Add Item" form to add new products to the inventory.
    - View the current state of the inventory in the main dashboard.
    - Explore the transaction history for each item.