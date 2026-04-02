import hashlib
import json
import threading
from datetime import datetime

import mysql.connector


class Blockchain:
    # Connections are passed in per operation, not stored in this class.
    def __init__(self):
        self.chain = []
        self.difficulty = "00"  # Simple difficulty (2 leading zeros)
        self._chain_lock = threading.RLock()
        self._db_lock_name = "inventory_blockchain_lock"
        self._has_current_hash_column = False

    def _normalize_transactions(self, transactions):
        """Returns a canonical transaction list for deterministic hashing."""
        normalized = []
        for tx in transactions:
            normalized.append({
                'user': tx.get('user'),
                'action': tx.get('action'),
                'item': tx.get('item'),
                'quantity': int(tx.get('quantity', 0)),
                'timestamp': round(float(tx.get('timestamp', 0.0)), 6),
                'branch': tx.get('branch')
            })

        return sorted(
            normalized,
            key=lambda tx: (
                tx['timestamp'],
                str(tx.get('user', '')),
                str(tx.get('action', '')),
                str(tx.get('item', '')),
                tx['quantity'],
                str(tx.get('branch', ''))
            )
        )

    def _pow_payload(self, previous_hash, transactions, block_index, nonce, timestamp=None):
        """Builds deterministic payload for proof-of-work hashing."""
        payload = {
            'index': int(block_index),
            'previous_hash': previous_hash,
            'transactions': self._normalize_transactions(transactions),
            'nonce': int(nonce)
        }

        # Kept only for backward-compatible validation of legacy blocks.
        if timestamp is not None:
            payload['timestamp'] = float(timestamp)

        return payload

    def _pow_hash(self, previous_hash, transactions, block_index, nonce, timestamp=None):
        payload = self._pow_payload(previous_hash, transactions, block_index, nonce, timestamp)
        encoded_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded_payload).hexdigest()

    def _legacy_sort_transactions(self, transactions):
        """Sorts transactions like the original implementation (by timestamp only)."""
        legacy_transactions = []
        for tx in transactions:
            legacy_transactions.append({
                'user': tx.get('user'),
                'action': tx.get('action'),
                'item': tx.get('item'),
                'quantity': int(tx.get('quantity', 0)),
                'timestamp': float(tx.get('timestamp', 0.0)),
                'branch': tx.get('branch')
            })
        return sorted(legacy_transactions, key=lambda tx: tx['timestamp'])

    def _legacy_hash(self, block):
        """Original block-hash format used by existing ledgers."""
        block_copy = {
            'index': int(block.get('index', 0)),
            'timestamp': float(block.get('timestamp', 0.0)),
            'nonce': int(block.get('nonce', 0)),
            'previous_hash': block.get('previous_hash', ''),
            'transactions': self._legacy_sort_transactions(block.get('transactions', []))
        }
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def _legacy_pow_hash(self, previous_hash, transactions, block_index, nonce, timestamp):
        """Legacy PoW payload hash used by older blocks."""
        payload = {
            'index': int(block_index),
            'timestamp': float(timestamp),
            'previous_hash': previous_hash,
            'transactions': self._legacy_sort_transactions(transactions),
            'nonce': int(nonce)
        }
        encoded_payload = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(encoded_payload).hexdigest()

    def _prepare_transactions_for_storage(self, transactions):
        """Normalizes transactions to match DB DATETIME precision for stable hashing."""
        prepared = []
        for tx in transactions:
            tx_time = datetime.fromtimestamp(float(tx['timestamp'])).replace(microsecond=0)
            prepared.append({
                'user': tx.get('user'),
                'action': tx.get('action'),
                'item': tx.get('item'),
                'quantity': int(tx.get('quantity', 0)),
                'timestamp': tx_time.timestamp(),
                'branch': tx.get('branch')
            })
        return prepared

    def _acquire_db_lock(self, cursor, timeout_seconds=15):
        """Uses a DB advisory lock so multiple app instances cannot mine at once."""
        cursor.execute("SELECT GET_LOCK(%s, %s);", (self._db_lock_name, timeout_seconds))
        lock_result = cursor.fetchone()
        if not lock_result or lock_result[0] != 1:
            raise RuntimeError("Could not acquire blockchain database lock.")

    def _release_db_lock(self, cursor):
        """Best-effort release for the DB advisory lock."""
        try:
            cursor.execute("SELECT RELEASE_LOCK(%s);", (self._db_lock_name,))
            cursor.fetchone()
            while cursor.nextset():
                cursor.fetchall()
        except mysql.connector.Error:
            # Ignore release failures: lock also auto-releases when connection closes.
            pass

    def _detect_schema_features(self, cursor):
        """Detects optional schema capabilities for backward compatibility."""
        cursor.execute("SHOW COLUMNS FROM blockchain LIKE 'current_hash';")
        self._has_current_hash_column = cursor.fetchone() is not None

    def _reload_chain_headers(self, cursor):
        if self._has_current_hash_column:
            cursor.execute(
                "SELECT block_index, timestamp, nonce, previous_hash, current_hash "
                "FROM blockchain ORDER BY block_index;"
            )
        else:
            cursor.execute(
                "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain ORDER BY block_index;"
            )
        blocks = cursor.fetchall()
        self.chain = []

        for block in blocks:
            header = {
                'index': int(block[0]),
                'timestamp': block[1].timestamp(),
                'nonce': int(block[2]),
                'previous_hash': block[3]
            }
            if self._has_current_hash_column:
                header['current_hash'] = block[4]
            self.chain.append(header)

    def sync_chain_headers(self, db_connection):
        """Public helper to refresh in-memory chain headers from DB."""
        with self._chain_lock:
            with db_connection.cursor() as cursor:
                self._detect_schema_features(cursor)
                self._reload_chain_headers(cursor)

    def _get_next_block_index(self, cursor):
        """Gets the next block index from DB state, not in-memory length."""
        cursor.execute("SELECT block_index FROM blockchain ORDER BY block_index DESC LIMIT 1 FOR UPDATE;")
        last_block = cursor.fetchone()
        return 1 if not last_block else int(last_block[0]) + 1

    def load_chain(self, db_connection):
        """Loads blockchain headers and validates ledger integrity on startup."""
        try:
            with self._chain_lock:
                with db_connection.cursor() as cursor:
                    self._detect_schema_features(cursor)
                    self._reload_chain_headers(cursor)

                if not self.chain:
                    print("No blockchain in DB, creating Genesis block...")
                    with db_connection.cursor() as genesis_cursor:
                        self._acquire_db_lock(genesis_cursor)
                        try:
                            # Re-check after lock because another instance may have created genesis.
                            self._reload_chain_headers(genesis_cursor)
                            if not self.chain:
                                genesis_nonce = self.proof_of_work('0', [], block_index=1)
                                self.create_block(
                                    genesis_cursor,
                                    nonce=genesis_nonce,
                                    previous_hash='0',
                                    transactions=[],
                                    block_index=1,
                                    skip_pow_validation=True
                                )
                            self._release_db_lock(genesis_cursor)
                        except Exception:
                            self._release_db_lock(genesis_cursor)
                            raise

                    db_connection.commit()
                    print("Genesis block committed to database.")

                with db_connection.cursor() as validation_cursor:
                    if not self.is_chain_valid(validation_cursor):
                        raise RuntimeError("Blockchain validation failed. The ledger may be tampered with.")

                print("Blockchain successfully loaded and validated.")

        except Exception as err:
            db_connection.rollback()
            raise RuntimeError(f"Error loading blockchain: {err}") from err

    def get_block_with_transactions(self, cursor, block_index):
        """Fetches a single block header and its transactions from the DB."""
        try:
            if self._has_current_hash_column:
                cursor.execute(
                    "SELECT block_index, timestamp, nonce, previous_hash, current_hash "
                    "FROM blockchain WHERE block_index = %s;",
                    (block_index,)
                )
            else:
                cursor.execute(
                    "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain WHERE block_index = %s;",
                    (block_index,)
                )
            block = cursor.fetchone()
            if not block:
                return None

            block_dict = {
                'index': int(block[0]),
                'timestamp': block[1].timestamp(),
                'nonce': int(block[2]),
                'previous_hash': block[3],
                'transactions': []
            }
            if self._has_current_hash_column:
                block_dict['current_hash'] = block[4]

            cursor.execute(
                "SELECT user, action, item, quantity, timestamp, branch "
                "FROM transactions WHERE block_index = %s ORDER BY tx_id;",
                (block_index,)
            )
            txs = cursor.fetchall()

            for tx in txs:
                block_dict['transactions'].append({
                    'user': tx[0],
                    'action': tx[1],
                    'item': tx[2],
                    'quantity': int(tx[3]),
                    'timestamp': tx[4].timestamp(),
                    'branch': tx[5]
                })

            return block_dict
        except mysql.connector.Error as err:
            print(f"Error fetching full block {block_index}: {err}")
            return None

    def get_previous_block(self, cursor):
        """Gets the latest full block (header plus transactions) from DB."""
        if self.chain:
            previous_block_header = self.chain[-1]
            return self.get_block_with_transactions(cursor, previous_block_header['index'])

        cursor.execute("SELECT block_index FROM blockchain ORDER BY block_index DESC LIMIT 1;")
        latest = cursor.fetchone()
        if not latest:
            return None
        return self.get_block_with_transactions(cursor, int(latest[0]))

    def hash(self, block):
        """Hashes a full block using legacy-compatible format for chain linkage."""
        return self._legacy_hash(block)

    def proof_of_work(self, previous_hash, transactions, block_index):
        """Finds a nonce that satisfies the configured difficulty."""
        nonce = 0
        while True:
            hash_attempt = self._pow_hash(previous_hash, transactions, block_index, nonce)
            if hash_attempt.startswith(self.difficulty):
                return nonce
            nonce += 1

    def is_valid_proof(self, previous_hash, transactions, nonce, block_index, timestamp=None):
        """
        Validates PoW for deterministic payload.
        Also supports legacy payload that included timestamp.
        """
        deterministic_hash = self._pow_hash(previous_hash, transactions, block_index, nonce)
        if deterministic_hash.startswith(self.difficulty):
            return True

        if timestamp is not None:
            timestamp_hash = self._pow_hash(previous_hash, transactions, block_index, nonce, timestamp=timestamp)
            if timestamp_hash.startswith(self.difficulty):
                return True

            legacy_hash = self._legacy_pow_hash(previous_hash, transactions, block_index, nonce, timestamp)
            if legacy_hash.startswith(self.difficulty):
                return True

        return False

    def create_block(self, cursor, nonce, previous_hash, transactions, block_index, skip_pow_validation=False):
        """Persists a block header and its transactions to DB and updates in-memory headers."""
        transactions = self._normalize_transactions(transactions)
        transactions_for_storage = self._prepare_transactions_for_storage(transactions)
        timestamp_obj = datetime.now()

        if (not skip_pow_validation) and (not self.is_valid_proof(previous_hash, transactions, nonce, block_index)):
            raise ValueError("Invalid nonce for configured proof-of-work difficulty.")

        block_for_hash = {
            'index': int(block_index),
            'timestamp': timestamp_obj.timestamp(),
            'nonce': int(nonce),
            'previous_hash': previous_hash,
            'transactions': transactions_for_storage
        }
        current_hash = self.hash(block_for_hash)

        if self._has_current_hash_column:
            cursor.execute(
                "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash, current_hash) "
                "VALUES (%s, %s, %s, %s, %s)",
                (int(block_index), timestamp_obj, int(nonce), previous_hash, current_hash)
            )
        else:
            cursor.execute(
                "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash) VALUES (%s, %s, %s, %s)",
                (int(block_index), timestamp_obj, int(nonce), previous_hash)
            )

        for tx in transactions_for_storage:
            tx_timestamp = datetime.fromtimestamp(float(tx['timestamp']))
            cursor.execute(
                "INSERT INTO transactions (block_index, user, action, item, quantity, timestamp, branch) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    int(block_index),
                    tx['user'],
                    tx['action'],
                    tx['item'],
                    int(tx['quantity']),
                    tx_timestamp,
                    tx['branch']
                )
            )

        block_header = {
            'index': int(block_index),
            'timestamp': timestamp_obj.timestamp(),
            'nonce': int(nonce),
            'previous_hash': previous_hash
        }
        if self._has_current_hash_column:
            block_header['current_hash'] = current_hash

        if not self.chain or self.chain[-1]['index'] < block_header['index']:
            self.chain.append(block_header)

        return {
            'index': int(block_index),
            'timestamp': timestamp_obj.timestamp(),
            'nonce': int(nonce),
            'previous_hash': previous_hash,
            'current_hash': current_hash,
            'transactions': transactions_for_storage
        }

    def mine_and_create_block(self, cursor, transactions):
        """Serializes mining + insert to keep chain order and hash links consistent."""
        if not transactions:
            raise ValueError("Cannot mine an empty transaction batch.")

        with self._chain_lock:
            self._acquire_db_lock(cursor)
            try:
                # Refresh headers to avoid stale in-memory state.
                self._reload_chain_headers(cursor)

                previous_block = self.get_previous_block(cursor)
                if previous_block is None:
                    raise RuntimeError("Cannot create a block without an existing genesis block.")

                previous_hash = self.hash(previous_block)
                block_index = self._get_next_block_index(cursor)
                nonce = self.proof_of_work(previous_hash, transactions, block_index)

                return self.create_block(
                    cursor,
                    nonce=nonce,
                    previous_hash=previous_hash,
                    transactions=transactions,
                    block_index=block_index
                )
            finally:
                self._release_db_lock(cursor)

    def is_chain_valid(self, cursor):
        """Validates hash linkage and proof-of-work across the chain."""
        with self._chain_lock:
            self._detect_schema_features(cursor)
            self._reload_chain_headers(cursor)
            if not self.chain:
                return True

            previous_block_full = None
            legacy_pow_skipped = 0
            for i, current_block_header in enumerate(self.chain):
                current_block_full = self.get_block_with_transactions(cursor, current_block_header['index'])
                if current_block_full is None:
                    print(f"Chain invalid: Failed to fetch full data for block {current_block_header['index']}")
                    return False

                # Genesis block linkage check.
                if i == 0:
                    if current_block_full['previous_hash'] != '0':
                        print("Chain invalid: Genesis block previous_hash must be '0'.")
                        return False
                    previous_block_full = current_block_full
                    continue

                expected_previous_hash = self.hash(previous_block_full)
                if current_block_full['previous_hash'] != expected_previous_hash:
                    print(f"Chain invalid: Hash linkage mismatch at block {current_block_full['index']}")
                    return False

                if self._has_current_hash_column:
                    expected_current_hash = self.hash(current_block_full)
                    if current_block_full.get('current_hash') != expected_current_hash:
                        print(f"Chain invalid: Stored hash mismatch at block {current_block_full['index']}")
                        return False

                proof_valid = self.is_valid_proof(
                    current_block_full['previous_hash'],
                    current_block_full.get('transactions', []),
                    current_block_full['nonce'],
                    current_block_full['index'],
                    timestamp=current_block_full['timestamp']
                )

                if not proof_valid:
                    # Older ledgers did not persist the PoW timestamp input, so strict
                    # legacy PoW re-validation is not always possible after the fact.
                    if self._has_current_hash_column and current_block_full.get('current_hash'):
                        print(f"Chain invalid: Invalid proof-of-work at block {current_block_full['index']}")
                        return False
                    else:
                        legacy_pow_skipped += 1

                previous_block_full = current_block_full

            if legacy_pow_skipped:
                print(f"Warning: Strict PoW validation skipped for {legacy_pow_skipped} legacy block(s).")

            return True