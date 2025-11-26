# blockchain_module.py
import hashlib
import json
import time
import mysql.connector
from datetime import datetime

# --- Database Connection ---
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',
    database='inventory_db'
)
cursor = db.cursor()


class Blockchain:
    def __init__(self, branch):
        self.branch = branch
        self.chain = []
        self.pending_transactions = []
        self.load_chain()

    def load_chain(self):
        cursor.execute(
            "SELECT block_index, timestamp, nonce, previous_hash, branch "
            "FROM blockchain WHERE branch = %s ORDER BY block_index;",
            (self.branch,)
        )
        blocks = cursor.fetchall()
        for block in blocks:
            block_dict = {
                'index': block[0],
                'timestamp': block[1].timestamp(),
                'nonce': block[2],
                'previous_hash': block[3],
                'branch': block[4],
                'transactions': []
            }
            cursor.execute(
                "SELECT user, action, item, quantity, timestamp "
                "FROM transactions WHERE block_index = %s AND branch = %s;",
                (block[0], self.branch)
            )
            txs = cursor.fetchall()
            for tx in txs:
                block_dict['transactions'].append({
                    'user': tx[0],
                    'action': tx[1],
                    'item': tx[2],
                    'quantity': tx[3],
                    'timestamp': tx[4].timestamp()
                })
            self.chain.append(block_dict)
        if not self.chain:
            self.create_block(nonce=1, previous_hash='0')

    def create_block(self, nonce, previous_hash):
        block_index = len(self.chain) + 1
        timestamp = datetime.now()
        block = {
            'index': block_index,
            'timestamp': time.mktime(timestamp.timetuple()),
            'nonce': nonce,
            'previous_hash': previous_hash,
            'branch': self.branch,
            'transactions': self.pending_transactions
        }

        cursor.execute(
            "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash, branch) "
            "VALUES (%s, %s, %s, %s, %s)",
            (block_index, timestamp, nonce, previous_hash, self.branch)
        )
        db.commit()

        for tx in self.pending_transactions:
            tx_timestamp = datetime.fromtimestamp(tx['timestamp'])
            cursor.execute(
                "INSERT INTO transactions (block_index, user, action, item, quantity, timestamp, branch) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (block_index, tx['user'], tx['action'], tx['item'], tx['quantity'], tx_timestamp, self.branch)
            )
        db.commit()

        self.pending_transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_nonce):
        new_nonce = 1
        while True:
            hash_operation = hashlib.sha256(str(new_nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                return new_nonce
            new_nonce += 1

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block['previous_hash'] != self.hash(previous_block):
                return False
            previous_nonce = previous_block['nonce']
            current_nonce = current_block['nonce']
            hash_operation = hashlib.sha256(str(current_nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
        return True
    