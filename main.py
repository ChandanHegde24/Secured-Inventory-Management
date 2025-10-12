import hashlib
import json
import time
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import messagebox, ttk

# MySQL connection setup (update credentials if needed)
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',        # Add MySQL password if any
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


def load_users():
    cursor.execute("SELECT username, pin, branch FROM users;")
    user_rows = cursor.fetchall()
    return {username: {'pin': pin, 'branch': branch} for username, pin, branch in user_rows}


class InventorySystem:
    def __init__(self, root):
        self.root = root
        self.root.title('Multi-Branch Inventory Management System')
        self.root.geometry('900x650')
        self.inventory = {}
        self.users = load_users()
        self.current_user = None
        self.current_branch = None
        self.blockchain = None
        self.loginscreen()

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def loginscreen(self):
        self.clear_root()
        self.root.configure(bg="#e6f7ff")

        login_frame = Frame(self.root, bg="#d1e7dd", bd=2)
        login_frame.pack(expand=True, fill="both", padx=40, pady=40)

        Label(
            login_frame,
            text="Multi-Branch Inventory Login",
            font=("Arial", 28, "bold"),
            bg="#d1e7dd",
            fg="#0a3d62",
            pady=16
        ).pack()

        Label(login_frame, text="Select Branch", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=12)
        self.branch_var = StringVar()
        branch_combo = ttk.Combobox(
            login_frame,
            textvariable=self.branch_var,
            values=["Inventory_1", "Inventory_2"],
            state="readonly",
            font=("Arial", 16)
        )
        branch_combo.pack(pady=8)
        branch_combo.set("Inventory_1")

        Label(login_frame, text="User ID", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=12)
        self.user_entry = Entry(login_frame, font=("Arial", 16), bg="#f5f6fa", fg="#222f3e")
        self.user_entry.pack(ipady=10, pady=8)

        Label(login_frame, text="PIN", font=("Arial", 18), bg="#d1e7dd", fg="#303960").pack(pady=12)
        self.pin_entry = Entry(login_frame, font=("Arial", 16), show="*", bg="#f5f6fa", fg="#222f3e")
        self.pin_entry.pack(ipady=10, pady=8)

        Button(
            login_frame,
            text="Login",
            font=("Arial", 16, "bold"),
            bg="#62d0ff",
            fg="#182c61",
            command=self.login
        ).pack(pady=24)

        info_frame = Frame(login_frame, bg="#d1e7dd")
        info_frame.pack(pady=20)
        Label(
            info_frame,
            text="Sample Login Credentials:",
            font=("Arial", 14, "bold"),
            bg="#d1e7dd",
            fg="#303960"
        ).pack()
        credentials_text = """
Inventory_1: admin1/1234, user1/1111, manager1/5678
Inventory_2: admin2/4321, user2/2222, manager2/8765
"""
        Label(
            info_frame,
            text=credentials_text,
            font=("Arial", 12),
            bg="#d1e7dd",
            fg="#555",
            justify=LEFT
        ).pack()

    def login(self):
        user = self.user_entry.get()
        pin = self.pin_entry.get()
        selected_branch = self.branch_var.get()

        if not selected_branch:
            messagebox.showerror('Login Failed', 'Please select a branch')
            return

        if user in self.users:
            user_data = self.users[user]
            if user_data['pin'] == pin and user_data['branch'] == selected_branch:
                self.current_user = user
                self.current_branch = selected_branch
                self.blockchain = Blockchain(self.current_branch)
                self.main_screen()
            else:
                messagebox.showerror('Login Failed', 'Invalid credentials or wrong branch')
        else:
            messagebox.showerror('Login Failed', 'Invalid user ID or PIN')

    def main_screen(self):
        self.clear_root()

        header_frame = Frame(self.root, bg="#2c3e50")
        header_frame.pack(fill="x", pady=(0, 10))
        Label(
            header_frame,
            text=f'Welcome {self.current_user} - {self.current_branch}',
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
        scrollbar = ttk.Scrollbar(inventory_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.load_inventory()
        self.load_inventory_display()

        input_frame = Frame(self.root, bg="#ecf0f1", bd=2, relief="raised")
        input_frame.pack(pady=10, padx=20, fill="x")

        Label(input_frame, text='Item Name', bg="#ecf0f1", font=('Arial', 12)).grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.item_entry = Entry(input_frame, font=('Arial', 12))
        self.item_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        Label(input_frame, text='Quantity', bg="#ecf0f1", font=('Arial', 12)).grid(
            row=1, column=0, padx=5, pady=5, sticky="w"
        )
        self.qty_entry = Entry(input_frame, font=('Arial', 12))
        self.qty_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        input_frame.grid_columnconfigure(1, weight=1)

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
        Button(
            button_frame,
            text='Delete Product',
            command=self.delete_product,
            bg="#e74c3c",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)
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
            bg="#95a5a6",
            fg="white",
            font=('Arial', 12, 'bold')
        ).pack(side="left", padx=5)

    def load_inventory(self):
        cursor.execute("SELECT item, quantity FROM inventory WHERE branch = %s;", (self.current_branch,))
        data = cursor.fetchall()
        self.inventory = {item: qty for item, qty in data}

    def load_inventory_display(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for item, qty in self.inventory.items():
            self.tree.insert('', END, values=(item, qty))

    def save_inventory_item(self, item, qty):
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
        item = self.item_entry.get().strip()
        try:
            qty = int(self.qty_entry.get())
        except Exception:
            messagebox.showerror('Invalid Input', 'Quantity must be an integer')
            return

        if not item:
            messagebox.showerror('Invalid Input', 'Item name cannot be empty')
            return

        prev_qty = self.inventory.get(item, 0)
        new_qty = prev_qty + qty
        self.inventory[item] = new_qty
        self.save_inventory_item(item, new_qty)

        transaction = {
            'user': self.current_user,
            'action': 'Add/Update',
            'item': item,
            'quantity': qty,
            'timestamp': time.time(),
            'branch': self.current_branch
        }
        self.blockchain.add_transaction(transaction)

        previous_block = self.blockchain.get_previous_block()
        previous_nonce = previous_block['nonce']
        nonce = self.blockchain.proof_of_work(previous_nonce)
        previous_hash = self.blockchain.hash(previous_block)
        self.blockchain.create_block(nonce, previous_hash)

        self.load_inventory_display()
        self.item_entry.delete(0, END)
        self.qty_entry.delete(0, END)
        messagebox.showinfo('Success', f'Stock for {item} updated by {qty} in {self.current_branch}')

    def delete_product(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror('No Selection', 'Select a product row to delete')
            return

        item_vals = self.tree.item(selected[0], 'values')
        if not item_vals:
            messagebox.showerror('Error', 'Unable to read selected item')
            return

        item_name = item_vals[0]
        if not messagebox.askyesno('Confirm Delete', f'Delete product "{item_name}" from {self.current_branch}?'):
            return

        try:
            cursor.execute(
                "DELETE FROM inventory WHERE item=%s AND branch=%s",
                (item_name, self.current_branch)
            )
            db.commit()
            if item_name in self.inventory:
                del self.inventory[item_name]
            self.tree.delete(selected[0])

            transaction = {
                'user': self.current_user,
                'action': 'Delete',
                'item': item_name,
                'quantity': 0,
                'timestamp': time.time(),
                'branch': self.current_branch
            }
            self.blockchain.add_transaction(transaction)

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
        if not self.blockchain.chain:
            messagebox.showinfo('Blockchain', f'Blockchain is empty for {self.current_branch}')
            return

        blocks_text = f'Blockchain Ledger for {self.current_branch}\n' + '=' * 50 + '\n\n'
        for block in self.blockchain.chain:
            blocks_text += f"Block {block['index']} - Timestamp: {time.ctime(block['timestamp'])}\n"
            blocks_text += f"Previous Hash: {block['previous_hash']}\n"
            blocks_text += f"Nonce: {block['nonce']}\n"
            blocks_text += f"Branch: {block.get('branch', 'N/A')}\n"
            blocks_text += "Transactions:\n"
            for tx in block['transactions']:
                blocks_text += (
                    f"- User: {tx['user']}, Action: {tx['action']}, Item: {tx['item']}, "
                    f"Quantity: {tx['quantity']}, Time: {time.ctime(tx['timestamp'])}\n"
                )
            blocks_text += '\n'

        blockchain_window = Toplevel(self.root)
        blockchain_window.title(f'Blockchain Ledger - {self.current_branch}')
        blockchain_window.geometry('900x600')

        text_frame = Frame(blockchain_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        txt = Text(text_frame, wrap=WORD, width=80, height=30, font=('Courier', 10))
        txt_scrollbar = Scrollbar(text_frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=txt_scrollbar.set)
        txt.insert(END, blocks_text)
        txt.config(state=DISABLED)
        txt.pack(side="left", fill="both", expand=True)
        txt_scrollbar.pack(side="right", fill="y")


if __name__ == '__main__':
    root = Tk()
    app = InventorySystem(root)
    root.mainloop()