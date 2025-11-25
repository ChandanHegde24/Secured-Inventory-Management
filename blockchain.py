import hashlib
import json
import time
import mysql.connector
from datetime import datetime

class Blockchain:
    # Connections will be passed in per-operation, not stored in the class.
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = "00"  # Simple difficulty (2 leading zeros)

    def load_chain(self, db_connection):
        """Loads only the blockchain HEADERS from the database on startup."""
        try:
            with db_connection.cursor() as cursor:
                cursor.execute(
                    "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain ORDER BY block_index;"
                )
                blocks = cursor.fetchall()
                self.chain = []  # Clear local chain before loading

                for block in blocks:
                    block_dict = {
                        'index': block[0],
                        'timestamp': block[1].timestamp(),
                        'nonce': block[2],
                        'previous_hash': block[3],
                        # 'transactions' key is deliberately omitted to save memory
                    }
                    self.chain.append(block_dict)

            if not self.chain:
                print("No blockchain in DB, creating Genesis block...")
                with db_connection.cursor() as genesis_cursor:
                    self.create_block(genesis_cursor, nonce=1, previous_hash='0')
                db_connection.commit()  # Commit the Genesis block
                print("Genesis block committed to database.")

            # Run validation *after* any potential Genesis block
            with db_connection.cursor() as validation_cursor:
                if not self.is_chain_valid(validation_cursor):
                    print("CRITICAL: Blockchain validation FAILED. The ledger may be tampered with!")
                else:
                    print("Blockchain successfully loaded and validated.")

        except mysql.connector.Error as err:
            print(f"Error loading blockchain: {err}")
            db_connection.rollback()
            if not self.chain:
                # Fallback for an empty/corrupt DB
                print("Creating in-memory Genesis block as fallback.")
                block_index = 1
                timestamp_obj = datetime.now()
                timestamp = time.mktime(timestamp_obj.timetuple())
                block = {
                    'index': block_index,
                    'timestamp': timestamp,
                    'nonce': 1,
                    'previous_hash': '0',
                    'transactions': self.pending_transactions
                }
                self.pending_transactions = []
                # Convert to header-only before appending
                block_header = {k: v for k, v in block.items() if k != 'transactions'}
                self.chain.append(block_header)

    def get_block_with_transactions(self, cursor, block_index):
        """Fetches a single block header AND its transactions from the DB."""
        try:
            # Fetch header
            cursor.execute(
                "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain WHERE block_index = %s;",
                (block_index,)
            )
            block = cursor.fetchone()
            if not block:
                return None

            block_dict = {
                'index': block[0],
                'timestamp': block[1].timestamp(),
                'nonce': block[2],
                'previous_hash': block[3],
                'transactions': []
            }

            # Fetch transactions
            cursor.execute(
                "SELECT user, action, item, quantity, timestamp, branch "
                "FROM transactions WHERE block_index = %s;",
                (block_index,)
            )
            txs = cursor.fetchall()
            for tx in txs:
                block_dict['transactions'].append({
                    'user': tx[0], 'action': tx[1], 'item': tx[2],
                    'quantity': tx[3], 'timestamp': tx[4].timestamp(), 'branch': tx[5]
                })
            return block_dict
        except mysql.connector.Error as err:
            print(f"Error fetching full block {block_index}: {err}")
            return None

    def create_block(self, cursor, nonce, previous_hash):
        """Saves a new block and its transactions to the DB using the provided cursor."""
        block_index = len(self.chain) + 1
        timestamp = datetime.now()
        block = {
            'index': block_index,
            'timestamp': time.mktime(timestamp.timetuple()),
            'nonce': nonce,
            'previous_hash': previous_hash,
            'transactions': self.pending_transactions
        }

        try:
            # Save block to blockchain table
            cursor.execute(
                "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash) "
                "VALUES (%s, %s, %s, %s)",
                (block_index, timestamp, nonce, previous_hash)
            )

            # Save transactions to transactions table
            for tx in self.pending_transactions:
                tx_timestamp = datetime.fromtimestamp(tx['timestamp'])
                cursor.execute(
                    "INSERT INTO transactions (block_index, user, action, item, quantity, timestamp, branch) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (block_index, tx['user'], tx['action'], tx['item'], tx['quantity'], tx_timestamp, tx['branch'])
                )

            self.pending_transactions = []

            # Append a header-only dict to the in-memory chain
            block_header = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'nonce': block['nonce'],
                'previous_hash': block['previous_hash']
            }
            self.chain.append(block_header)

            # Return the full block, as the caller might need it
            return block

        except mysql.connector.Error as err:
            print(f"Error creating block: {err}")
            raise err  # Re-raise to be caught by the calling logic's transaction

    def get_previous_block(self, cursor):
        """Gets the full (header + TXs) previous block from the DB."""
        if not self.chain:
            return None
        # self.chain[-1] is just the header
        previous_block_header = self.chain[-1]
        # We must fetch the full block from the DB to be able to hash it
        return self.get_block_with_transactions(cursor, previous_block_header['index'])

    def hash(self, block):
        """Hashes a full block (header + transactions)."""
        block_copy = block.copy()
        # Sort transactions for consistent hashing
        block_copy['transactions'] = sorted(block_copy.get('transactions', []), key=lambda x: x['timestamp'])
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def proof_of_work(self, previous_hash, transactions):
        """
        Simple Proof-of-Work (PoW):
        - Find a 'nonce' that, when hashed with the previous hash
          and transactions, results in a hash with the required difficulty (e.g., "00").
        """
        # Create a block template to hash
        block_data = {
            'index': len(self.chain) + 1,
            'timestamp': time.mktime(datetime.now().timetuple()),
            'previous_hash': previous_hash,
            'transactions': sorted(transactions, key=lambda x: x['timestamp'])
            # 'nonce' will be added in the loop
        }

        nonce = 0
        while True:
            block_data['nonce'] = nonce
            hash_attempt = self.hash(block_data)  # Use the existing hash function

            if hash_attempt.startswith(self.difficulty):
                # Found a valid nonce
                return nonce
            nonce += 1

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def is_chain_valid(self, cursor):
        """
        Validates the chain by fetching full blocks as needed
        to re-calculate hashes.
        """
        for i in range(1, len(self.chain)):
            current_block_header = self.chain[i]

            # To validate, we need the *full* previous block (with TXs)
            previous_block_full = self.get_block_with_transactions(cursor, self.chain[i - 1]['index'])

            if previous_block_full is None:
                print(f"Chain invalid: Failed to fetch full data for block {self.chain[i - 1]['index']}")
                return False

            # Check hash integrity
            if current_block_header['previous_hash'] != self.hash(previous_block_full):
                print(f"Chain invalid: Hash mismatch for block {i}")
                return False

        return True