import hashlib
import json
import time
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import messagebox, ttk

# MySQL connection setup
# --- IMPORTANT ---
# Make sure your database is created and the tables are set up.
# You can use the 'setup_database.sql' file provided in previous responses.
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',
    database='inventory_db'
)
cursor = db.cursor()


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.load_chain()

    def load_chain(self):
        """Loads the entire blockchain from the database on startup."""
        try:
            cursor.execute(
                "SELECT block_index, timestamp, nonce, previous_hash FROM blockchain ORDER BY block_index;"
            )
            blocks = cursor.fetchall()
            self.chain = [] # Clear local chain before loading
            
            for block in blocks:
                block_dict = {
                    'index': block[0],
                    'timestamp': block[1].timestamp(),
                    'nonce': block[2],
                    'previous_hash': block[3],
                    'transactions': []
                }
                
                # Get transactions for this block
                cursor.execute(
                    "SELECT user, action, item, quantity, timestamp, branch "
                    "FROM transactions WHERE block_index = %s;",
                    (block[0],)
                )
                txs = cursor.fetchall()
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
                # If no blocks in DB, create the Genesis block
                self.create_block(nonce=1, previous_hash='0')
                
        except mysql.connector.Error as err:
            print(f"Error loading blockchain: {err}")
            # Handle error appropriately, maybe raise it
            if not self.chain:
                 # Critical error if DB fails and chain is empty, create Genesis in memory
                 print("Creating in-memory Genesis block as fallback.")
                 # This won't be saved if DB is down, but allows app to run
                 # Call the original create_block logic but without DB part if it fails
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
            
            db.commit()

            self.pending_transactions = []
            self.chain.append(block)
            return block
            
        except mysql.connector.Error as err:
            db.rollback()
            print(f"Error creating block: {err}")
            return None # Indicate failure

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
        # Create a copy of the block to avoid modifying the original
        block_copy = block.copy()
        # Ensure transactions are sorted for consistent hashing
        block_copy['transactions'] = sorted(block_copy.get('transactions', []), key=lambda x: x['timestamp'])
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()


    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Re-hash the previous block to check integrity
            if current_block['previous_hash'] != self.hash(previous_block):
                print(f"Chain invalid: Hash mismatch for block {i}")
                return False
                
            previous_nonce = previous_block['nonce']
            current_nonce = current_block['nonce']
            hash_operation = hashlib.sha256(str(current_nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                print(f"Chain invalid: PoW incorrect for block {i}")
                return False
        return True


def load_users():
    """Loads all user credentials from the database."""
    cursor.execute("SELECT username, pin, branch FROM users;")
    user_rows = cursor.fetchall()
    # {username: {'pin': '1234', 'branch': 'Inventory_1'}}
    return {username: {'pin': pin, 'branch': branch} for username, pin, branch in user_rows}


class InventorySystem:
    def __init__(self, root):
        self.root = root
        self.root.title('Multi-Branch Inventory Management System')
        self.root.geometry('900x700')
        self.inventory = {} # In-memory cache for the *current* branch
        self.users = load_users()
        self.current_user = None
        self.current_branch = None
        # Used for the transfer dropdown
        self.all_branches = ["Inventory_1", "Inventory_2"] 
        self.blockchain = Blockchain()
        self.search_var = None
        self.search_entry = None
        self.loginscreen()

    def clear_root(self):
        """Destroys all widgets in the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def loginscreen(self):
        """Displays the login UI."""
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

        Button(
            login_frame,
            text="Login",
            font=("Arial", 16, "bold"),
            bg="#62d0ff",
            fg="#182c61",
            command=self.login,
            width=20
        ).pack(pady=24)

        # --- Info box for sample logins ---
        info_frame = Frame(login_frame, bg="#f0f4f7", bd=1, relief="solid")
        info_frame.pack(pady=20, padx=20, fill="x")
        Label(
            info_frame,
            text="Sample Login Credentials:",
            font=("Arial", 14, "bold"),
            bg="#f0f4f7",
            fg="#303960"
        ).pack(pady=(5,2))
        credentials_text = """
Inventory_1: admin1/1234, user1/1111, manager1/5678
Inventory_2: admin2/4321, user2/2222, manager2/8765
"""
        Label(
            info_frame,
            text=credentials_text,
            font=("Arial", 12),
            bg="#f0f4f7",
            fg="#555",
            justify=LEFT
        ).pack(pady=(0, 10))

    def login(self):
        """Validates user credentials against loaded users."""
        user = self.user_entry.get()
        pin = self.pin_entry.get()
        selected_branch = self.branch_var.get()

        if not selected_branch:
            messagebox.showerror('Login Failed', 'Please select a branch')
            return

        if user in self.users:
            user_data = self.users[user]
            # Check PIN and if user is assigned to the selected branch
            if user_data['pin'] == pin and user_data['branch'] == selected_branch:
                self.current_user = user
                self.current_branch = selected_branch
                self.main_screen()
            else:
                messagebox.showerror('Login Failed', 'Invalid credentials or wrong branch')
        else:
            messagebox.showerror('Login Failed', 'Invalid user ID or PIN')

    def main_screen(self):
        """Displays the main inventory management UI."""
        self.clear_root()

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

        # --- Inventory Tree View ---
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

        self.load_inventory() # Load from DB into self.inventory
        self.load_inventory_display() # Populate tree from self.inventory

        # --- Search Bar (Live filter + DB LIKE) ---
        search_frame = Frame(self.root, bg="#ecf0f1", bd=2, relief="groove")
        search_frame.pack(pady=8, padx=20, fill="x")

        Label(search_frame, text='Search Product', bg="#ecf0f1",
              font=('Arial', 12)).grid(row=0, column=0, padx=5, pady=6, sticky="w")

        self.search_var = StringVar()
        self.search_entry = Entry(search_frame, textvariable=self.search_var, font=('Arial', 12))
        self.search_entry.grid(row=0, column=1, padx=5, pady=6, sticky="ew")

        Button(search_frame, text='Clear', command=self.clear_search,
               bg="#95a5a6", fg="white", font=('Arial', 11, 'bold')).grid(row=0, column=2, padx=5, pady=6)

        Button(search_frame, text='DB Search', command=self.db_search_inventory,
               bg="#34495e", fg="white", font=('Arial', 11, 'bold')).grid(row=0, column=3, padx=5, pady=6)

        search_frame.grid_columnconfigure(1, weight=1)
        # Bind KeyRelease to update tree on every keystroke
        self.search_entry.bind('<KeyRelease>', self.on_search_key)

        # --- Input Frame for Add/Update ---
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
        
        Button(
            button_frame,
            text='Add/Update Stock',
            command=self.add_update_stock,
            bg="#27ae60",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        # --- NEW STOCK TRANSFER BUTTON ---
        Button(
            button_frame,
            text='Stock Transfer',
            command=self.open_stock_transfer_window, # New method
            bg="#8e44ad", # Purple
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        Button(
            button_frame,
            text='Delete Product',
            command=self.delete_product,
            bg="#e74c3c",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)

        # Only show View Blockchain for admins and managers
        if 'admin' in self.current_user.lower() or 'manager' in self.current_user.lower():
            Button(
                button_frame,
                text='View Blockchain',
                command=self.view_blockchain,
                bg="#3498db",
                fg="white",
                font=('Arial', 12, 'bold')
            ).pack(side="left", padx=5)
            
        Button(
            button_frame,
            text='Switch Branch',
            command=self.loginscreen,
            bg="#f39c12",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
        
        Button(
            button_frame,
            text='Logout',
            command=self.root.quit,
            bg="#7f8c8d",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)

    def load_inventory(self):
        """Loads inventory from DB for the *current branch* into the in-memory dict."""
        cursor.execute("SELECT item, quantity FROM inventory WHERE branch = %s;", (self.current_branch,))
        data = cursor.fetchall()
        self.inventory = {item: qty for item, qty in data}

    def load_inventory_display(self):
        """Populates the Treeview with items from the in-memory dict."""
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        # Sort items alphabetically for display
        sorted_items = sorted(self.inventory.items())
        
        for item, qty in sorted_items:
            self.tree.insert('', END, values=(item, qty))

    def save_inventory_item(self, item, qty):
        """Saves a single item's quantity to the DB for the current branch."""
        cursor.execute(
            "SELECT quantity FROM inventory WHERE item=%s AND branch=%s",
            (item, self.current_branch)
        )
        result = cursor.fetchone()
        if result:
            cursor.execute(
                "UPDATE inventory SET quantity=%s WHERE item=%s AND branch=%s",
                (qty, item, self.current_branch)
            )
        else:
            cursor.execute(
                "INSERT INTO inventory (item, quantity, branch) VALUES (%s, %s, %s)",
                (item, qty, self.current_branch)
            )
        db.commit()

    def add_update_stock(self):
        """Adds or removes stock based on the main screen's input fields."""
        item = self.item_entry.get().strip()
        try:
            # This is the change in quantity (can be positive or negative)
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

        prev_qty = self.inventory.get(item, 0)
        new_qty = prev_qty + qty_change

        # Add check to prevent stock from going below zero
        if new_qty < 0:
            messagebox.showerror('Invalid Quantity', f'Cannot remove {abs(qty_change)} units. Only {prev_qty} units of "{item}" are in stock.')
            return

        self.inventory[item] = new_qty
        self.save_inventory_item(item, new_qty)

        # Log the *change* in quantity (e.g., +10 or -5)
        transaction = {
            'user': self.current_user,
            'action': 'Add/Update',
            'item': item,
            'quantity': qty_change, 
            'timestamp': time.time(),
            'branch': self.current_branch
        }
        self.blockchain.add_transaction(transaction)

        # Mine a new block for this transaction
        previous_block = self.blockchain.get_previous_block()
        previous_nonce = previous_block['nonce']
        nonce = self.blockchain.proof_of_work(previous_nonce)
        previous_hash = self.blockchain.hash(previous_block)
        self.blockchain.create_block(nonce, previous_hash)

        # Refresh the filtered view if a query exists, else full
        self.on_search_key()

        self.item_entry.delete(0, END)
        self.qty_entry.delete(0, END)
        
        # Show a different message for adding vs removing
        if qty_change > 0:
            messagebox.showinfo('Success', f'Added {qty_change} units to "{item}". New total: {new_qty}.')
        else:
            messagebox.showinfo('Success', f'Removed {abs(qty_change)} units from "{item}". New total: {new_qty}.')

    def delete_product(self):
        """Deletes a product entirely from the current branch inventory."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror('No Selection', 'Select a product row to delete')
            return

        item_vals = self.tree.item(selected[0], 'values')
        if not item_vals:
            messagebox.showerror('Error', 'Unable to read selected item')
            return

        item_name = item_vals[0]
        if not messagebox.askyesno('Confirm Delete', f'Delete product "{item_name}" from {self.current_branch}?\nThis cannot be undone and will be logged to the blockchain.'):
            return

        try:
            # Delete from database
            cursor.execute(
                "DELETE FROM inventory WHERE item=%s AND branch=%s",
                (item_name, self.current_branch)
            )
            db.commit()
            
            # Delete from in-memory cache
            if item_name in self.inventory:
                del self.inventory[item_name]
                
            # Delete from treeview
            self.tree.delete(selected[0])

            # Log this deletion to the blockchain
            transaction = {
                'user': self.current_user,
                'action': 'Delete Product',
                'item': item_name,
                'quantity': 0, # Quantity is 0 as it's a deletion
                'timestamp': time.time(),
                'branch': self.current_branch
            }
            self.blockchain.add_transaction(transaction)

            # Mine the block
            previous_block = self.blockchain.get_previous_block()
            previous_nonce = previous_block['nonce']
            nonce = self.blockchain.proof_of_work(previous_nonce)
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)

            messagebox.showinfo('Deleted', f'Product "{item_name}" deleted successfully from {self.current_branch}')
        except Exception as e:
            db.rollback()
            messagebox.showerror('Error', f'Failed to delete product: {e}')

    def view_blockchain(self):
        """Shows the entire global blockchain in a new window."""
        if not self.blockchain.chain:
            messagebox.showinfo('Blockchain', 'The Global Blockchain is empty.')
            return

        # Format the blockchain data for display
        blocks_text = 'Global Blockchain Ledger (All Branches)\n' + '=' * 50 + '\n\n'
        for block in self.blockchain.chain:
            blocks_text += f"Block {block['index']} - Timestamp: {time.ctime(block['timestamp'])}\n"
            blocks_text += f"Previous Hash: {block['previous_hash']}\n"
            blocks_text += f"Nonce: {block['nonce']}\n"
        
            blocks_text += "Transactions:\n"
            if not block['transactions']:
                blocks_text += "   - No transactions in this block (Genesis block)\n"
            
            # Sort transactions for readability
            sorted_txs = sorted(block.get('transactions', []), key=lambda x: x['timestamp'])
            
            for tx in sorted_txs:
                blocks_text += (
                    f" - Branch: {tx['branch']:<12} | User: {tx['user']:<10} | Action: {tx['action']:<15} | "
                    f"Item: {tx['item']:<20} | Qty: {tx['quantity']:<5} | "
                    f"Time: {time.ctime(tx['timestamp'])}\n"
                )

            blocks_text += '\n' + '-'*60 + '\n\n'

        # Create the Toplevel window
        blockchain_window = Toplevel(self.root)
        blockchain_window.title('Global Blockchain Ledger')
        blockchain_window.geometry('950x600')

        text_frame = Frame(blockchain_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        txt = Text(text_frame, wrap=NONE, width=80, height=30, font=('Courier', 10))
        
        # Add Scrollbars
        v_scrollbar = Scrollbar(text_frame, orient="vertical", command=txt.yview)
        h_scrollbar = Scrollbar(text_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        txt.insert(END, blocks_text)
        txt.config(state=DISABLED) # Make read-only
        
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        txt.pack(side="left", fill="both", expand=True)

    # ---------------------------------
    # --- NEW Stock Transfer Methods ---
    # ---------------------------------

    def open_stock_transfer_window(self):
        """Opens a new Toplevel window for handling stock transfers."""
        transfer_window = Toplevel(self.root)
        transfer_window.title('Stock Transfer')
        transfer_window.geometry('450x350')
        transfer_window.configure(bg="#f0f4f7")
        # Make this window modal
        transfer_window.grab_set()

        form_frame = Frame(transfer_window, bg="#f0f4f7", pady=15, padx=15)
        form_frame.pack(expand=True, fill="both")

        Label(form_frame, text=f"From Branch: {self.current_branch}", font=('Arial', 12, 'bold'), bg="#f0f4f7").grid(row=0, column=0, columnspan=3, pady=5, sticky="w")

        Label(form_frame, text="To Branch:", font=('Arial', 12), bg="#f0f4f7").grid(row=1, column=0, pady=5, sticky="w")
        
        # Get target branches (all branches *except* current)
        target_branches = [b for b in self.all_branches if b != self.current_branch]
        
        to_branch_var = StringVar()
        to_branch_combo = ttk.Combobox(
            form_frame,
            textvariable=to_branch_var,
            values=target_branches,
            state="readonly",
            font=("Arial", 12)
        )
        to_branch_combo.grid(row=1, column=1, pady=5, sticky="ew", columnspan=2)
        if target_branches:
            to_branch_combo.set(target_branches[0]) # Default to first target

        Label(form_frame, text="Item:", font=('Arial', 12), bg="#f0f4f7").grid(row=2, column=0, pady=5, sticky="w")
        
        # Get items from current inventory (only items with stock > 0)
        available_items = sorted([item for item, qty in self.inventory.items() if qty > 0])
        
        item_var = StringVar()
        item_combo = ttk.Combobox(
            form_frame,
            textvariable=item_var,
            values=available_items,
            state="readonly",
            font=("Arial", 12)
        )
        item_combo.grid(row=2, column=1, pady=5, sticky="ew")

        # Label to show current stock
        stock_label = Label(form_frame, text="(In Stock: --)", font=('Arial', 10, 'italic'), bg="#f0f4f7")
        stock_label.grid(row=2, column=2, padx=5, sticky="w")
        
        def on_item_select(event=None):
            """Updates the stock label when an item is selected."""
            selected_item = item_var.get()
            current_stock = self.inventory.get(selected_item, 0)
            stock_label.config(text=f"(In Stock: {current_stock})")

        item_combo.bind("<<ComboboxSelected>>", on_item_select)


        Label(form_frame, text="Quantity:", font=('Arial', 12), bg="#f0f4f7").grid(row=3, column=0, pady=5, sticky="w")
        qty_entry = Entry(form_frame, font=("Arial", 12))
        qty_entry.grid(row=3, column=1, pady=5, sticky="ew")

        form_frame.grid_columnconfigure(1, weight=1)

        confirm_btn = Button(
            form_frame,
            text="Confirm Transfer",
            font=('Arial', 12, 'bold'),
            bg="#27ae60",
            fg="white",
            command=lambda: self.execute_stock_transfer(
                item_var.get(),
                qty_entry.get(),
                to_branch_var.get(),
                transfer_window # Pass the window to close it
            )
        )
        confirm_btn.grid(row=4, column=0, columnspan=3, pady=20)


    def execute_stock_transfer(self, item, qty_str, to_branch, window):
        """Validates and executes the stock transfer, updating DB and blockchain."""
        
        if not item or not to_branch:
            messagebox.showerror('Invalid Input', 'Please select an item and a target branch.', parent=window)
            return
            
        try:
            quantity = int(qty_str)
            if quantity <= 0:
                raise ValueError("Quantity must be positive")
        except ValueError:
            messagebox.showerror('Invalid Input', 'Quantity must be a positive integer (e.g., 1, 5, 10).', parent=window)
            return

        # Check for sufficient stock in the *current* branch
        current_stock = self.inventory.get(item, 0)
        if quantity > current_stock:
            messagebox.showerror('Insufficient Stock', f'Cannot transfer {quantity} units. Only {current_stock} units of "{item}" are in {self.current_branch}.', parent=window)
            return

        # Final confirmation
        if not messagebox.askyesno('Confirm Transfer', f'Transfer {quantity} units of "{item}" from {self.current_branch} to {to_branch}?', parent=window):
            return

        try:
            # --- Transaction Start ---
            
            # 1. Remove stock from the *current* branch (source)
            new_stock_source = current_stock - quantity
            self.inventory[item] = new_stock_source # Update in-memory cache
            self.save_inventory_item(item, new_stock_source) # Updates DB for current branch

            # 2. Add stock to the *target* branch (destination)
            # We must do this with a direct SQL query as we are not logged into that branch
            cursor.execute(
                "SELECT quantity FROM inventory WHERE item=%s AND branch=%s",
                (item, to_branch)
            )
            result = cursor.fetchone()
            to_branch_current_qty = result[0] if result else 0
            
            new_stock_target = to_branch_current_qty + quantity

            if result:
                # Item exists, update it
                cursor.execute(
                    "UPDATE inventory SET quantity=%s WHERE item=%s AND branch=%s",
                    (new_stock_target, item, to_branch)
                )
            else:
                # Item does not exist, insert it
                cursor.execute(
                    "INSERT INTO inventory (item, quantity, branch) VALUES (%s, %s, %s)",
                    (item, new_stock_target, to_branch)
                )
            
            # Commit the change for the target branch
            # Note: save_inventory_item already committed for the source branch
            db.commit() 

            # 3. Log both transactions to the blockchain
            
            tx_time = time.time()
            
            # Transaction 1: Transfer Out (Negative quantity)
            tx_out = {
                'user': self.current_user,
                'action': 'Transfer Out',
                'item': item,
                'quantity': -quantity, 
                'timestamp': tx_time,
                'branch': self.current_branch
            }
            self.blockchain.add_transaction(tx_out)

            # Transaction 2: Transfer In (Positive quantity)
            tx_in = {
                'user': self.current_user, # Logged by the user who initiated it
                'action': 'Transfer In',
                'item': item,
                'quantity': quantity, 
                'timestamp': tx_time + 1, # Ensure slightly different timestamp
                'branch': to_branch
            }
            self.blockchain.add_transaction(tx_in)
            
            # 4. Mine the block with both transactions
            previous_block = self.blockchain.get_previous_block()
            previous_nonce = previous_block['nonce']
            nonce = self.blockchain.proof_of_work(previous_nonce)
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)
            
            # 5. Update UI and close
            
            # Refresh the main screen's tree view
            self.on_search_key() # This re-filters or re-loads all
                
            messagebox.showinfo('Success', f'Transferred {quantity} units of "{item}" to {to_branch} successfully.', parent=window.master) # Show on main window
            window.destroy() # Close the transfer window

        except Exception as e:
            db.rollback() # Rollback any DB changes
            # We must also rollback the *in-memory* change to the source inventory
            self.inventory[item] = current_stock
            # And reload the tree to be safe
            self.load_inventory_display()
            messagebox.showerror('Transfer Failed', f'An error occurred: {e}\nTransaction rolled back.', parent=window)


    # ---------------------------
    # Search & Filter Integration
    # ---------------------------
    def on_search_key(self, event=None):
        """Client-side live filter over in-memory inventory dict."""
        query = (self.search_var.get() if self.search_var else '').strip().lower()
        
        # Clear current rows
        for iid in self.tree.get_children():
            self.tree.delete(iid)
            
        if not query:
            # If search is empty, show all (load_inventory_display sorts)
            self.load_inventory_display()
            return
            
        # filter by substring in item name
        # Sort results alphabetically
        filtered_items = sorted([
            (item, qty) for item, qty in self.inventory.items() 
            if query in item.lower()
        ])
        
        for item, qty in filtered_items:
            self.tree.insert('', END, values=(item, qty))

    def clear_search(self):
        """Clears the search box and reloads the full inventory display."""
        if self.search_var:
            self.search_var.set('')
        # Show all original cached items
        self.load_inventory_display()

    def db_search_inventory(self):
        """Server-side LIKE search; replaces table view with DB results."""
        query = (self.search_var.get() if self.search_var else '').strip()
        like_query = f"%{query}%"
        
        cursor.execute(
            "SELECT item, quantity FROM inventory WHERE branch = %s AND item LIKE %s ORDER BY item",
            (self.current_branch, like_query)
        )
        rows = cursor.fetchall()
        
        # Update tree with DB results only (do not mutate full cache)
        for iid in self.tree.get_children():
            self.tree.delete(iid)
            
        for item, qty in rows:
            self.tree.insert('', END, values=(item, qty))
        
        if not rows and query:
            messagebox.showinfo("DB Search", f'No items found in {self.current_branch} matching "{query}".')
        elif not query:
             messagebox.showinfo("DB Search", 'Search term is empty. Showing all items from DB.')
             # Re-load full list from cache for consistency
             self.load_inventory_display()


if __name__ == '__main__':
    root = Tk()
    app = InventorySystem(root)
    root.mainloop()