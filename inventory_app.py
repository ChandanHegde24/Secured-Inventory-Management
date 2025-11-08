# inventory_app.py
import hashlib
import json
import time
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import messagebox, ttk
import threading  # --- NEW ---: For running long tasks off the main UI thread
import bcrypt     # --- NEW ---: For secure PIN hashing
import os         # --- NEW ---: For reading environment variables
from dotenv import load_dotenv # --- NEW ---: For loading the .env file

# --- NEW ---: Load credentials from .env file
load_dotenv()

DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME')

# --- NEW ---: A function to manage the database connection
def get_db_connection():
    """
    Establishes a new database connection.
    This should be called per-thread to ensure thread safety.
    """
    try:
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )
        return db
    except mysql.connector.Error as err:
        print(f"CRITICAL DB ERROR: {err}")
        # This is a startup-time error, so a simple print/exit is okay.
        # We can't show a messagebox if Tkinter isn't running.
        return None

class Blockchain:
    def __init__(self, db_connection):
        self.chain = []
        self.pending_transactions = []
        # --- CHANGED ---: Use the passed-in connection
        self.db = db_connection
        self.cursor = self.db.cursor()
        self.load_chain()

    def load_chain(self):
        """Loads the entire blockchain from the database on startup."""
        try:
            self.cursor.execute(
                "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain ORDER BY block_index;"
            )
            blocks = self.cursor.fetchall()
            self.chain = []  # Clear local chain before loading
            
            for block in blocks:
                block_dict = {
                    'index': block[0],
                    'timestamp': block[1].timestamp(),
                    'nonce': block[2],
                    'previous_hash': block[3],
                    'transactions': []
                }
                
                # Get transactions for this block
                self.cursor.execute(
                    "SELECT user, action, item, quantity, timestamp, branch "
                    "FROM transactions WHERE block_index = %s;",
                    (block[0],)
                )
                txs = self.cursor.fetchall()
                for tx in txs:
                    block_dict['transactions'].append({
                        'user': tx[0],
                        'action': tx[1],
                        'item': tx[2],
                        'quantity': tx[3],
                        'timestamp': tx[4].timestamp(),
                        'branch': tx[5]
                    })
                self.chain.append(block_dict)
                
            if not self.chain:
                print("No blockchain in DB, creating Genesis block...")
                # Since this is part of an atomic commit, we'll let the caller commit.
                self.create_block(nonce=1, previous_hash='0')
            
            # --- NEW ---: Validate the chain on load
            if not self.is_chain_valid():
                print("CRITICAL: Blockchain validation FAILED. The ledger may be tampered with!")
                # In a real app, you might halt or show a severe warning.
            else:
                print("Blockchain successfully loaded and validated.")
                
        except mysql.connector.Error as err:
            print(f"Error loading blockchain: {err}")
            self.db.rollback()
            if not self.chain:
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
                self.chain.append(block)

    def create_block(self, nonce, previous_hash):
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
            self.cursor.execute(
                "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash) "
                "VALUES (%s, %s, %s, %s)",
                (block_index, timestamp, nonce, previous_hash)
            )
            
            # Save transactions to transactions table
            for tx in self.pending_transactions:
                tx_timestamp = datetime.fromtimestamp(tx['timestamp'])
                self.cursor.execute(
                    "INSERT INTO transactions (block_index, user, action, item, quantity, timestamp, branch) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (block_index, tx['user'], tx['action'], tx['item'], tx['quantity'], tx_timestamp, tx['branch'])
                )
            
            # --- CHANGED ---: Commit must be handled by the calling function
            # self.db.commit() # REMOVED FOR ATOMICITY
            
            self.pending_transactions = []
            self.chain.append(block)
            return block
            
        except mysql.connector.Error as err:
            # --- CHANGED ---: Rollback handled by caller
            print(f"Error creating block: {err}")
            raise err # Re-raise the error so the caller can roll back

    def get_previous_block(self):
        return self.chain[-1]

    # --- CHANGED ---: Proof of Work is removed.
    # It's not needed for a private, centralized ledger and causes UI freezes.

    def hash(self, block):
        block_copy = block.copy()
        block_copy['transactions'] = sorted(block_copy.get('transactions', []), key=lambda x: x['timestamp'])
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # 1. Check hash integrity
            if current_block['previous_hash'] != self.hash(previous_block):
                print(f"Chain invalid: Hash mismatch for block {i}")
                return False
            
            # --- CHANGED ---: Removed the Proof-of-Work check as it's no longer used.
            
        return True

class InventorySystem:
    def __init__(self, root):
        self.root = root
        self.root.title('Multi-Branch Inventory Management System')
        self.root.geometry('900x700')
        self.inventory = {}
        self.current_user = None
        self.current_branch = None
        self.all_branches = ["Inventory_1", "Inventory_2"] 
        
        # --- NEW ---: Thread-safe DB connection handling
        # self.db and self.cursor are now thread-local.
        # We create a "main" connection for the blockchain and initial load
        self.main_db = get_db_connection()
        if not self.main_db:
            root.withdraw() # Hide window
            messagebox.showerror("Fatal Error", "Could not connect to database. Check .env file and console.")
            root.quit()
            return
            
        self.blockchain = Blockchain(self.main_db)
        
        # --- NEW ---: Commit the Genesis block if it was just created
        if len(self.blockchain.chain) == 1 and self.blockchain.chain[0]['index'] == 1:
            try:
                self.main_db.commit()
                print("Genesis block committed to database.")
            except mysql.connector.Error as err:
                print(f"Error committing Genesis block: {err}")
                self.main_db.rollback()
        
        self.search_var = None
        self.search_entry = None
        self.loginscreen()

    # --- NEW ---: Wrapper to run functions in a new thread
    def start_thread(self, target_function, args=()):
        """Starts a target function in a new thread to avoid blocking the UI."""
        # 'daemon=True' ensures the thread exits when the main app exits
        thread = threading.Thread(target=target_function, args=args, daemon=True)
        thread.start()

    # --- NEW ---: Wrapper to show messages from background threads
    def show_message(self, type, title, message, parent=None):
        """Schedules a messagebox to be shown on the main thread."""
        if parent is None:
            parent = self.root
        
        if type == 'info':
            self.root.after(0, lambda: messagebox.showinfo(title, message, parent=parent))
        elif type == 'error':
            self.root.after(0, lambda: messagebox.showerror(title, message, parent=parent))
        elif type == 'askyesno':
            # This one is tricky as it needs a response.
            # For simplicity, we'll assume most thread-based 'askyesno' are handled
            # *before* starting the thread.
            pass

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def loginscreen(self):
        self.clear_root()
        self.root.configure(bg="#e6f7ff")

        login_frame = Frame(self.root, bg="#d1e7dd", bd=2, relief="solid")
        login_frame.pack(expand=True, padx=50, pady=50)

        Label(
            login_frame,
            text="Multi-Branch Inventory Login",
            font=("Arial", 28, "bold"),
            bg="#d1e7dd",
            fg="#0a3d62",
            pady=16
        ).pack(pady=(10, 20))

        Label(login_frame, text="Select Branch", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=5)
        self.branch_var = StringVar()
        branch_combo = ttk.Combobox(
            login_frame,
            textvariable=self.branch_var,
            values=self.all_branches,
            state="readonly",
            font=("Arial", 16)
        )
        branch_combo.pack(pady=8, padx=20, fill="x")
        branch_combo.set(self.all_branches[0]) # Default to first branch

        Label(login_frame, text="User ID", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=5)
        self.user_entry = Entry(login_frame, font=("Arial", 16), bg="#f5f6fa", fg="#222f3e", width=25)
        self.user_entry.pack(ipady=10, pady=8, padx=20)

        Label(login_frame, text="PIN", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=5)
        self.pin_entry = Entry(login_frame, font=("Arial", 16), show="*", bg="#f5f6fa", fg="#222f3e", width=25)
        self.pin_entry.pack(ipady=10, pady=8, padx=20)
        
        # --- CHANGED ---: Button command now calls the wrapper
        self.login_button = Button(
            login_frame,
            text="Login",
            font=("Arial", 16, "bold"),
            bg="#62d0ff",
            fg="#182c61",
            command=self.login, # This wrapper will call start_thread
            width=20
        )
        self.login_button.pack(pady=24)
        
        # Bind 'Enter' key to login
        self.root.bind('<Return>', self.login)

        info_frame = Frame(login_frame, bg="#f0f4f7", bd=1, relief="solid")
        info_frame.pack(pady=20, padx=20, fill="x")
        Label(
            info_frame,
            text="Sample Login Credentials (from DB):",
            font=("Arial", 14, "bold"),
            bg="#f0f4f7",
            fg="#303960"
        ).pack(pady=(5,2))
        Label(
            info_frame,
            text="Use your sample users (e.g., admin1/1234)",
            font=("Arial", 12),
            bg="#f0f4f7",
            fg="#555",
            justify=LEFT
        ).pack(pady=(0, 10))


    # --- CHANGED ---: Login is now a wrapper
    def login(self, event=None):
        """Wrapper to get UI data and start the login thread."""
        user = self.user_entry.get()
        pin = self.pin_entry.get()
        selected_branch = self.branch_var.get()
        
        if not selected_branch:
            messagebox.showerror('Login Failed', 'Please select a branch')
            return
        if not user or not pin:
            messagebox.showerror('Login Failed', 'User ID and PIN cannot be empty')
            return

        # --- NEW ---: Disable login button to prevent double-click
        self.login_button.config(state=DISABLED, text="Logging in...")
            
        # --- NEW ---: Run the actual login logic in a new thread
        self.start_thread(self.login_logic, args=(user, pin, selected_branch))

    # --- NEW ---: The actual login logic that runs in the background
    def login_logic(self, user, pin, selected_branch):
        """Validates user credentials against the database using bcrypt."""
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            
            # --- CHANGED ---: Query for *only* the user logging in
            cursor.execute(
                "SELECT pin, branch FROM users WHERE username = %s",
                (user,)
            )
            result = cursor.fetchone()
            
            if result:
                hashed_pin_from_db = result[0].encode('utf-8')
                user_branch = result[1]
                
                # Check PIN and if user is assigned to the selected branch
                if user_branch == selected_branch and bcrypt.checkpw(pin.encode('utf-8'), hashed_pin_from_db):
                    self.current_user = user
                    self.current_branch = selected_branch
                    # --- NEW ---: UI updates must run on the main thread
                    self.root.after(0, self.main_screen)
                else:
                    self.show_message('error', 'Login Failed', 'Invalid credentials or wrong branch')
            else:
                self.show_message('error', 'Login Failed', 'Invalid user ID or PIN')
                
        except mysql.connector.Error as err:
            self.show_message('error', 'Login Error', f'A database error occurred: {err}')
        except Exception as e:
            # This is where the "invalid salt" error would appear
            self.show_message('error', 'Login Error', f'An unexpected error occurred: {e}')
        finally:
            # --- NEW ---: Re-enable the login button on the main thread
            self.root.after(0, lambda: self.login_button.config(state=NORMAL, text="Login"))
            if db and db.is_connected():
                cursor.close()
                db.close()


    def main_screen(self):
        self.clear_root()
        self.root.unbind('<Return>') # Unbind enter key

        header_frame = Frame(self.root, bg="#2c3e50")
        header_frame.pack(fill="x", pady=(0, 10))
        Label(
            header_frame,
            text=f'Welcome {self.current_user} - Branch: {self.current_branch}',
            font=('Arial', 18, 'bold'),
            bg="#2c3e50",
            fg="white",
            pady=10
        ).pack()

        inventory_frame = Frame(self.root)
        inventory_frame.pack(pady=10, padx=20, fill="both", expand=True)
        Label(inventory_frame, text=f'{self.current_branch} Stock', font=('Arial', 16, 'bold')).pack()

        self.tree = ttk.Treeview(inventory_frame, columns=('Item', 'Quantity'), show='headings', height=15)
        self.tree.heading('Item', text='Item')
        self.tree.heading('Quantity', text='Quantity')
        self.tree.column('Item', width=400)
        self.tree.column('Quantity', width=100, anchor="center")
        
        scrollbar = ttk.Scrollbar(inventory_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # --- NEW ---: Bind click-to-edit
        self.tree.bind('<<TreeviewSelect>>', self.on_row_select)

        # --- CHANGED ---: Load inventory in a new thread
        self.start_thread(self.load_inventory_logic)

        search_frame = Frame(self.root, bg="#ecf0f1", bd=2, relief="groove")
        search_frame.pack(pady=8, padx=20, fill="x")
        Label(search_frame, text='Search Product', bg="#ecf0f1",
              font=('Arial', 12)).grid(row=0, column=0, padx=5, pady=6, sticky="w")
        self.search_var = StringVar()
        self.search_entry = Entry(search_frame, textvariable=self.search_var, font=('Arial', 12))
        self.search_entry.grid(row=0, column=1, padx=5, pady=6, sticky="ew")
        Button(search_frame, text='Clear', command=self.clear_search,
               bg="#95a5a6", fg="white", font=('Arial', 11, 'bold')).grid(row=0, column=2, padx=5, pady=6)
        # --- CHANGED ---: Removed DB Search button for simplicity
        search_frame.grid_columnconfigure(1, weight=1)
        self.search_entry.bind('<KeyRelease>', self.on_search_key)

        input_frame = Frame(self.root, bg="#ecf0f1", bd=2, relief="raised")
        input_frame.pack(pady=10, padx=20, fill="x")
        Label(input_frame, text='Item Name', bg="#ecf0f1", font=('Arial', 12)).grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.item_entry = Entry(input_frame, font=('Arial', 12))
        self.item_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        Label(input_frame, text='Quantity (e.g., 10 or -5)', bg="#ecf0f1", font=('Arial', 12)).grid(
            row=1, column=0, padx=5, pady=5, sticky="w"
        )
        self.qty_entry = Entry(input_frame, font=('Arial', 12))
        self.qty_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        # --- Main Button Frame ---
        button_frame = Frame(self.root)
        button_frame.pack(pady=10)
        
        # --- CHANGED ---: All button commands now call wrapper methods
        Button(
            button_frame,
            text='Add/Update Stock',
            command=self.add_update_stock, # Wrapper
            bg="#27ae60", fg="white", font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        Button(
            button_frame,
            text='Stock Transfer',
            command=self.open_stock_transfer_window, # This is fine, it just opens a window
            bg="#8e44ad", fg="white", font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        Button(
            button_frame,
            text='Delete Product',
            command=self.delete_product, # Wrapper
            bg="#e74c3c", fg="white", font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)

        if 'admin' in self.current_user.lower() or 'manager' in self.current_user.lower():
            Button(
                button_frame,
                text='View Blockchain',
                command=self.view_blockchain, # This is fine, it just reads memory
                bg="#3498db", fg="white", font=('Arial', 12, 'bold')
            ).pack(side="left", padx=5)
            
        Button(
            button_frame,
            text='Switch Branch',
            command=self.loginscreen,
            bg="#f39c12", fg="white", font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        Button(
            button_frame,
            text='Logout',
            command=self.root.quit,
            bg="#7f8c8d", fg="white", font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
    # --- NEW ---: Logic for populating entry boxes on row click
    def on_row_select(self, event=None):
        """Called when a user clicks a row in the treeview."""
        try:
            selected_item = self.tree.selection()[0]
            item_name = self.tree.item(selected_item, 'values')[0]
            
            # Clear existing entries
            self.item_entry.delete(0, END)
            self.qty_entry.delete(0, END)
            
            # Insert selected item name
            self.item_entry.insert(0, item_name)
        except IndexError:
            # User clicked an empty area, do nothing
            pass

    # --- NEW ---: Logic for loading inventory in a thread
    def load_inventory_logic(self):
        """Loads inventory from DB for the *current branch* into the in-memory dict."""
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("SELECT item, quantity FROM inventory WHERE branch = %s;", (self.current_branch,))
            data = cursor.fetchall()
            self.inventory = {item: qty for item, qty in data}
            
            # --- NEW ---: Schedule the UI update on the main thread
            self.root.after(0, self.load_inventory_display)
        except mysql.connector.Error as err:
            self.show_message('error', 'Load Error', f'Failed to load inventory: {err}')
        finally:
            if db and db.is_connected():
                cursor.close()
                db.close()

    def load_inventory_display(self):
        """Populates the Treeview with items from the in-memory dict. (Runs on main thread)"""
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        sorted_items = sorted(self.inventory.items())
        
        for item, qty in sorted_items:
            self.tree.insert('', END, values=(item, qty))

    # --- CHANGED ---: Renamed from save_inventory_item.
    # This now runs in a thread and does NOT commit.
    def save_inventory_item_logic(self, cursor, item, qty, branch):
        """
        Saves a single item's quantity to the DB for a given branch.
        DOES NOT COMMIT. Assumes it's part of a larger transaction.
        """
        cursor.execute(
            "SELECT quantity FROM inventory WHERE item=%s AND branch=%s FOR UPDATE",
            (item, branch)
        )
        result = cursor.fetchone()
        if result:
            cursor.execute(
                "UPDATE inventory SET quantity=%s WHERE item=%s AND branch=%s",
                (qty, item, branch)
            )
        else:
            cursor.execute(
                "INSERT INTO inventory (item, quantity, branch) VALUES (%s, %s, %s)",
                (item, qty, branch)
            )

    # --- CHANGED ---: Wrapper for add/update stock
    def add_update_stock(self):
        """Wrapper to get UI data and start the add/update thread."""
        # --- NEW ---: Normalize item name, .title() makes "laptop" and "Laptop" the same
        item = self.item_entry.get().strip().title()
        
        try:
            qty_change = int(self.qty_entry.get())
        except Exception:
            messagebox.showerror('Invalid Input', 'Quantity must be an integer (e.g., 10 or -5)')
            return

        if not item:
            messagebox.showerror('Invalid Input', 'Item name cannot be empty')
            return
            
        if qty_change == 0:
            messagebox.showinfo('No Change', 'Quantity change cannot be zero.')
            return

        # Start the background task
        self.start_thread(self.add_update_stock_logic, args=(item, qty_change))

    # --- NEW ---: The actual logic for adding/updating stock
    def add_update_stock_logic(self, item, qty_change):
        """Handles the DB and blockchain logic for updating stock."""
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            
            # --- NEW ---: Get fresh quantity from DB, not stale cache
            cursor.execute(
                "SELECT quantity FROM inventory WHERE item=%s AND branch=%s FOR UPDATE",
                (item, self.current_branch)
            )
            result = cursor.fetchone()
            prev_qty = result[0] if result else 0
            
            new_qty = prev_qty + qty_change

            if new_qty < 0:
                self.show_message('error', 'Invalid Quantity', f'Cannot remove {abs(qty_change)} units. Only {prev_qty} units of "{item}" are in stock.')
                return

            # 1. Save the inventory change
            self.save_inventory_item_logic(cursor, item, new_qty, self.current_branch)

            # 2. Log the transaction
            transaction = {
                'user': self.current_user,
                'action': 'Add/Update',
                'item': item,
                'quantity': qty_change, 
                'timestamp': time.time(),
                'branch': self.current_branch
            }
            # --- CHANGED ---: Use the main DB connection for the blockchain
            self.blockchain.db = db
            self.blockchain.cursor = cursor
            self.blockchain.add_transaction(transaction)

            # 3. Mine the block
            previous_block = self.blockchain.get_previous_block()
            # --- CHANGED ---: No PoW, so nonce is simple
            nonce = 0 
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)
            
            # 4. --- NEW ---: Commit everything at once
            db.commit()

            # 5. Update in-memory cache *after* successful commit
            self.inventory[item] = new_qty
            
            # 6. Schedule UI updates
            self.root.after(0, self.on_search_key) # Refresh tree
            self.root.after(0, lambda: self.item_entry.delete(0, END))
            self.root.after(0, lambda: self.qty_entry.delete(0, END))
            
            if qty_change > 0:
                self.show_message('info', 'Success', f'Added {qty_change} units to "{item}". New total: {new_qty}.')
            else:
                self.show_message('info', 'Success', f'Removed {abs(qty_change)} units from "{item}". New total: {new_qty}.')

        except mysql.connector.Error as err:
            if db: db.rollback()
            self.show_message('error', 'Error', f'Database error: {err}\nTransaction rolled back.')
        except Exception as e:
            if db: db.rollback()
            self.show_message('error', 'Error', f'An unexpected error occurred: {e}\nTransaction rolled back.')
        finally:
            if db and db.is_connected():
                db.close()


    # --- CHANGED ---: Wrapper for delete product
    def delete_product(self):
        """Wrapper to get UI data and start the delete thread."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror('No Selection', 'Select a product row to delete')
            return

        item_vals = self.tree.item(selected[0], 'values')
        if not item_vals:
            messagebox.showerror('Error', 'Unable to read selected item')
            return

        item_name = item_vals[0]
        if not messagebox.askyesno('Confirm Delete', f'Delete product "{item_name}" from {self.current_branch}?\nThis cannot be undone and will be logged.'):
            return
            
        self.start_thread(self.delete_product_logic, args=(item_name, selected[0]))

    # --- NEW ---: The actual logic for deleting a product
    def delete_product_logic(self, item_name, tree_item_id):
        """Handles the DB and blockchain logic for deleting a product."""
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()

            # 1. Delete from database
            cursor.execute(
                "DELETE FROM inventory WHERE item=%s AND branch=%s",
                (item_name, self.current_branch)
            )
            
            # 2. Log to blockchain
            transaction = {
                'user': self.current_user,
                'action': 'Delete Product',
                'item': item_name,
                'quantity': 0,
                'timestamp': time.time(),
                'branch': self.current_branch
            }
            # --- CHANGED ---: Use the thread's DB connection
            self.blockchain.db = db
            self.blockchain.cursor = cursor
            self.blockchain.add_transaction(transaction)

            # 3. Mine the block
            previous_block = self.blockchain.get_previous_block()
            nonce = 0 # No PoW
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)

            # 4. --- NEW ---: Commit everything at once
            db.commit()

            # 5. Update cache and UI
            if item_name in self.inventory:
                del self.inventory[item_name]
                
            self.root.after(0, lambda: self.tree.delete(tree_item_id))
            self.show_message('info', 'Deleted', f'Product "{item_name}" deleted successfully from {self.current_branch}')
            
        except mysql.connector.Error as err:
            if db: db.rollback()
            self.show_message('error', 'Error', f'Failed to delete product: {err}\nTransaction rolled back.')
        except Exception as e:
            if db: db.rollback()
            self.show_message('error', 'Error', f'An unexpected error occurred: {e}\nTransaction rolled back.')
        finally:
            if db and db.is_connected():
                db.close()

    def view_blockchain(self):
        # This just reads from memory, so it's fast and doesn't need a thread.
        if not self.blockchain.chain:
            messagebox.showinfo('Blockchain', 'The Global Blockchain is empty.')
            return
            
        blocks_text = 'Global Blockchain Ledger (All Branches)\n' + '=' * 50 + '\n\n'
        for block in self.blockchain.chain:
            blocks_text += f"Block {block['index']} - Timestamp: {time.ctime(block['timestamp'])}\n"
            blocks_text += f"Previous Hash: {block['previous_hash']}\n"
            blocks_text += f"Nonce: {block['nonce']}\n"
            blocks_text += "Transactions:\n"
            if not block['transactions']:
                blocks_text += "   - No transactions in this block (Genesis block)\n"
            sorted_txs = sorted(block.get('transactions', []), key=lambda x: x['timestamp'])
            for tx in sorted_txs:
                blocks_text += (
                    f" - Branch: {tx['branch']:<12} | User: {tx['user']:<10} | Action: {tx['action']:<15} | "
                    f"Item: {tx['item']:<20} | Qty: {tx['quantity']:<5} | "
                    f"Time: {time.ctime(tx['timestamp'])}\n"
                )
            blocks_text += '\n' + '-'*60 + '\n\n'
        blockchain_window = Toplevel(self.root)
        blockchain_window.title('Global Blockchain Ledger')
        blockchain_window.geometry('950x600')
        text_frame = Frame(blockchain_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        txt = Text(text_frame, wrap=NONE, width=80, height=30, font=('Courier', 10))
        v_scrollbar = Scrollbar(text_frame, orient="vertical", command=txt.yview)
        h_scrollbar = Scrollbar(text_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        txt.insert(END, blocks_text)
        txt.config(state=DISABLED) 
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        txt.pack(side="left", fill="both", expand=True)
        

    def open_stock_transfer_window(self):
        """Opens a new Toplevel window for handling stock transfers."""
        transfer_window = Toplevel(self.root)
        transfer_window.title('Stock Transfer')
        transfer_window.geometry('450x350')
        transfer_window.configure(bg="#f0f4f7")
        transfer_window.grab_set()

        form_frame = Frame(transfer_window, bg="#f0f4f7", pady=15, padx=15)
        form_frame.pack(expand=True, fill="both")

        Label(form_frame, text=f"From Branch: {self.current_branch}", font=('Arial', 12, 'bold'), bg="#f0f4f7").grid(row=0, column=0, columnspan=3, pady=5, sticky="w")
        Label(form_frame, text="To Branch:", font=('Arial', 12), bg="#f0f4f7").grid(row=1, column=0, pady=5, sticky="w")
        
        target_branches = [b for b in self.all_branches if b != self.current_branch]
        to_branch_var = StringVar()
        to_branch_combo = ttk.Combobox(
            form_frame, textvariable=to_branch_var, values=target_branches,
            state="readonly", font=("Arial", 12)
        )
        to_branch_combo.grid(row=1, column=1, pady=5, sticky="ew", columnspan=2)
        if target_branches:
            to_branch_combo.set(target_branches[0])

        Label(form_frame, text="Item:", font=('Arial', 12), bg="#f0f4f7").grid(row=2, column=0, pady=5, sticky="w")
        
        available_items = sorted([item for item, qty in self.inventory.items() if qty > 0])
        item_var = StringVar()
        item_combo = ttk.Combobox(
            form_frame, textvariable=item_var, values=available_items,
            state="readonly", font=("Arial", 12)
        )
        item_combo.grid(row=2, column=1, pady=5, sticky="ew")

        stock_label = Label(form_frame, text="(In Stock: --)", font=('Arial', 10, 'italic'), bg="#f0f4f7")
        stock_label.grid(row=2, column=2, padx=5, sticky="w")
        
        def on_item_select(event=None):
            selected_item = item_var.get()
            current_stock = self.inventory.get(selected_item, 0)
            stock_label.config(text=f"(In Stock: {current_stock})")
        item_combo.bind("<<ComboboxSelected>>", on_item_select)

        Label(form_frame, text="Quantity:", font=('Arial', 12), bg="#f0f4f7").grid(row=3, column=0, pady=5, sticky="w")
        qty_entry = Entry(form_frame, font=("Arial", 12))
        qty_entry.grid(row=3, column=1, pady=5, sticky="ew")

        form_frame.grid_columnconfigure(1, weight=1)

        # --- CHANGED ---: Button now calls the wrapper
        confirm_btn = Button(
            form_frame,
            text="Confirm Transfer",
            font=('Arial', 12, 'bold'),
            bg="#27ae60", fg="white",
            command=lambda: self.execute_stock_transfer(
                item_var.get(),
                qty_entry.get(),
                to_branch_var.get(),
                transfer_window
            )
        )
        confirm_btn.grid(row=4, column=0, columnspan=3, pady=20)


    # --- CHANGED ---: Wrapper for stock transfer
    def execute_stock_transfer(self, item, qty_str, to_branch, window):
        """Wrapper to validate UI input and start the transfer thread."""
        
        # --- NEW ---: Normalize item name
        item = item.strip().title()

        if not item or not to_branch:
            messagebox.showerror('Invalid Input', 'Please select an item and a target branch.', parent=window)
            return
            
        try:
            quantity = int(qty_str)
            if quantity <= 0:
                raise ValueError("Quantity must be positive")
        except ValueError:
            messagebox.showerror('Invalid Input', 'Quantity must be a positive integer.', parent=window)
            return

        # Check against in-memory cache first (quick check)
        current_stock = self.inventory.get(item, 0)
        if quantity > current_stock:
            messagebox.showerror('Insufficient Stock', f'Cannot transfer {quantity} units. Only {current_stock} units of "{item}" are in {self.current_branch}.', parent=window)
            return

        if not messagebox.askyesno('Confirm Transfer', f'Transfer {quantity} units of "{item}" from {self.current_branch} to {to_branch}?', parent=window):
            return

        # --- NEW ---: Start the threaded logic
        self.start_thread(self.execute_stock_transfer_logic, args=(item, quantity, to_branch, window))

    # --- NEW ---: The actual logic for ATOMIC stock transfer
    def execute_stock_transfer_logic(self, item, quantity, to_branch, window):
        """
        Executes the stock transfer as an ATOMIC transaction
        in a background thread.
        """
        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            
            # --- ATOMIC TRANSACTION START ---
            
            # 1. Get current stock from SOURCE branch (and lock the row)
            cursor.execute(
                "SELECT quantity FROM inventory WHERE item=%s AND branch=%s FOR UPDATE",
                (item, self.current_branch)
            )
            result = cursor.fetchone()
            current_stock_source = result[0] if result else 0
            
            # 2. Final server-side check
            if quantity > current_stock_source:
                self.show_message('error', 'Insufficient Stock', f'Stock level changed. Only {current_stock_source} units available.', parent=window)
                db.rollback()
                return
                
            # 3. Get current stock from TARGET branch (and lock the row)
            cursor.execute(
                "SELECT quantity FROM inventory WHERE item=%s AND branch=%s FOR UPDATE",
                (item, to_branch)
            )
            result = cursor.fetchone()
            current_stock_target = result[0] if result else 0
            
            # 4. Calculate new values
            new_stock_source = current_stock_source - quantity
            new_stock_target = current_stock_target + quantity
            
            # 5. Update SOURCE branch
            self.save_inventory_item_logic(cursor, item, new_stock_source, self.current_branch)
            
            # 6. Update TARGET branch
            self.save_inventory_item_logic(cursor, item, new_stock_target, to_branch)
            
            # 7. Log both transactions to blockchain
            tx_time = time.time()
            self.blockchain.db = db
            self.blockchain.cursor = cursor
            
            self.blockchain.add_transaction({
                'user': self.current_user, 'action': 'Transfer Out', 'item': item,
                'quantity': -quantity, 'timestamp': tx_time, 'branch': self.current_branch
            })
            self.blockchain.add_transaction({
                'user': self.current_user, 'action': 'Transfer In', 'item': item,
                'quantity': quantity, 'timestamp': tx_time + 1, 'branch': to_branch
            })
            
            # 8. Mine the block
            previous_block = self.blockchain.get_previous_block()
            nonce = 0 # No PoW
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)
            
            # 9. --- ATOMIC COMMIT ---
            # All DB changes (2 inventory updates, 1 block, 2 txs)
            # are saved in this single, atomic operation.
            db.commit()
            
            # 10. Update local cache and UI (on main thread)
            self.inventory[item] = new_stock_source
            
            self.root.after(0, self.on_search_key) # Refresh tree
            self.root.after(0, window.destroy) # Close popup
            self.show_message('info', 'Success', f'Transferred {quantity} units of "{item}" to {to_branch} successfully.')

        except mysql.connector.Error as err:
            if db: db.rollback()
            self.show_message('error', 'Transfer Failed', f'An error occurred: {err}\nTransaction rolled back.', parent=window)
        except Exception as e:
            if db: db.rollback()
            self.show_message('error', 'Transfer Failed', f'An unexpected error occurred: {e}\nTransaction rolled back.', parent=window)
        finally:
            if db and db.is_connected():
                db.close()


    def on_search_key(self, event=None):
        """Client-side live filter (no DB access, very fast)"""
        query = (self.search_var.get() if self.search_var else '').strip().lower()
        
        for iid in self.tree.get_children():
            self.tree.delete(iid)
            
        if not query:
            self.load_inventory_display()
            return
            
        filtered_items = sorted([
            (item, qty) for item, qty in self.inventory.items() 
            if query in item.lower()
        ])
        
        for item, qty in filtered_items:
            self.tree.insert('', END, values=(item, qty))

    def clear_search(self):
        if self.search_var:
            self.search_var.set('')
        self.load_inventory_display()

    # --- CHANGED ---: Removed db_search_inventory as it's redundant
    # with the faster, client-side filter.


if __name__ == '__main__':
    # --- CHANGED ---: Check for DB variables before starting
    if not all([DB_HOST, DB_USER, DB_NAME]):
        print("CRITICAL ERROR: Database credentials not found in .env file.")
        print("Please create a .env file with DB_HOST, DB_USER, DB_PASS, and DB_NAME.")
    else:
        root = Tk()
        app = InventorySystem(root)
        root.mainloop()
        
        # --- NEW ---: Gracefully close the main DB connection on exit
        if app.main_db and app.main_db.is_connected():
            app.main_db.close()
            print("Main database connection closed.")