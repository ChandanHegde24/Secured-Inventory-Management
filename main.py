import hashlib
import json
import time
import mysql.connector
from datetime import datetime
from tkinter import *
from tkinter import messagebox, ttk

# MySQL connection setup
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',        # Add MySQL password if any
    database='inventory_db'
)
cursor = db.cursor()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.load_chain()

    def load_chain(self):
        cursor.execute("SELECT * FROM blockchain ORDER BY block_index;")
        blocks = cursor.fetchall()
        for block in blocks:
            block_dict = {
                'index': block[1],
                'timestamp': block[2].timestamp(),
                'nonce': block[3],
                'previous_hash': block[4],
                'transactions': []
            }
            cursor.execute("SELECT user, action, item, quantity, timestamp FROM transactions WHERE block_index = %s;", (block[1],))
            txs = cursor.fetchall()
            for tx in txs:
                tx_dict = {
                    'user': tx[0],
                    'action': tx[1],
                    'item': tx[2],
                    'quantity': tx[3],
                    'timestamp': tx[4].timestamp()
                }
                block_dict['transactions'].append(tx_dict)
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
            'transactions': self.pending_transactions
        }
        cursor.execute(
            "INSERT INTO blockchain (block_index, timestamp, nonce, previous_hash) VALUES (%s, %s, %s, %s)",
            (block_index, timestamp, nonce, previous_hash)
        )
        db.commit()

        for tx in self.pending_transactions:
            tx_timestamp = datetime.fromtimestamp(tx['timestamp'])
            cursor.execute(
                "INSERT INTO transactions (block_index, user, action, item, quantity, timestamp) VALUES (%s, %s, %s, %s, %s, %s)",
                (block_index, tx['user'], tx['action'], tx['item'], tx['quantity'], tx_timestamp)
            )
        db.commit()

        self.pending_transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_nonce):
        new_nonce = 1
        check_nonce = False
        while not check_nonce:
            hash_operation = hashlib.sha256(str(new_nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_nonce = True
            else:
                new_nonce += 1
        return new_nonce

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
    cursor.execute("SELECT username, pin FROM users;")
    user_rows = cursor.fetchall()
    return {username: pin for username, pin in user_rows}

users = load_users()

class InventorySystem:
    def __init__(self, root):
        self.root = root
        self.root.title('Multi-Branch Inventory Management')
        self.blockchain = Blockchain()
        self.inventory = {}
        self.load_inventory()
        self.users = load_users()
        self.current_user = None
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
            text="Login",
            font=("Arial", 28, "bold"),
            bg="#d1e7dd",
            fg="#0a3d62",
            pady=16
        ).pack()
        Label(
            login_frame,
            text="User ID",
            font=("Arial", 18),
            bg="#d1e7dd",
            fg="#303960"
        ).pack(pady=12)
        self.user_entry = Entry(
            login_frame,
            font=("Arial", 16),
            bg="#f5f6fa",
            fg="#222f3e"
        )
        self.user_entry.pack(ipady=10, pady=8)
        Label(
            login_frame,
            text="PIN",
            font=("Arial", 18),
            bg="#d1e7dd",
            fg="#303960"
        ).pack(pady=12)
        self.pin_entry = Entry(
            login_frame,
            font=("Arial", 16),
            show="*",
            bg="#f5f6fa",
            fg="#222f3e"
        )
        self.pin_entry.pack(ipady=10, pady=8)
        Button(
            login_frame,
            text="Login",
            font=("Arial", 16, "bold"),
            bg="#62d0ff",
            fg="#182c61",
            command=self.login
        ).pack(pady=24)

    def login(self):
        user = self.user_entry.get()
        pin = self.pin_entry.get()
        if user in self.users and self.users[user] == pin:
            self.current_user = user
            self.main_screen()
        else:
            messagebox.showerror('Login Failed', 'Invalid user ID or PIN')

    def main_screen(self):
        self.clear_root()
        Label(self.root, text=f'Welcome {self.current_user}', font=('Arial', 16)).pack(pady=10)

        self.tree = ttk.Treeview(self.root, columns=('Item', 'Quantity'), show='headings')
        self.tree.heading('Item', text='Item')
        self.tree.heading('Quantity', text='Quantity')
        self.tree.pack(pady=10)

        self.load_inventory_display()

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text='Item Name').grid(row=0, column=0)
        self.item_entry = Entry(frame)
        self.item_entry.grid(row=0, column=1)

        Label(frame, text='Quantity').grid(row=1, column=0)
        self.qty_entry = Entry(frame)
        self.qty_entry.grid(row=1, column=1)

        Button(frame, text='Add/Update Stock', command=self.add_update_stock).grid(row=2, column=0, columnspan=2, pady=5)
        Button(frame, text='Delete Product', command=self.delete_product).grid(row=3, column=0, columnspan=2, pady=5)

        Button(self.root, text='View Blockchain', command=self.view_blockchain).pack(pady=5)
        Button(self.root, text='Logout', command=self.loginscreen).pack(pady=5)

    def load_inventory(self):
        cursor.execute("SELECT item, quantity FROM inventory;")
        data = cursor.fetchall()
        self.inventory = {item: qty for item, qty in data}

    def load_inventory_display(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for item, qty in self.inventory.items():
            self.tree.insert('', END, values=(item, qty))

    def save_inventory_item(self, item, qty):
        cursor.execute("SELECT quantity FROM inventory WHERE item=%s", (item,))
        result = cursor.fetchone()
        if result:
            cursor.execute("UPDATE inventory SET quantity=%s WHERE item=%s", (qty, item))
        else:
            cursor.execute("INSERT INTO inventory (item, quantity) VALUES (%s, %s)", (item, qty))
        db.commit()

    def add_update_stock(self):
        item = self.item_entry.get().strip()
        try:
            qty = int(self.qty_entry.get())
        except:
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
            'timestamp': time.time()
        }
        self.blockchain.add_transaction(transaction)

        previous_block = self.blockchain.get_previous_block()
        previous_nonce = previous_block['nonce']
        nonce = self.blockchain.proof_of_work(previous_nonce)
        previous_hash = self.blockchain.hash(previous_block)
        self.blockchain.create_block(nonce, previous_hash)

        self.load_inventory_display()
        messagebox.showinfo('Success', f'Stock for {item} updated by {qty}')

    def delete_product(self):
        # ensure there is a selection
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror('No Selection', 'Select a product row to delete')
            return

        # get selected item's values (Item, Quantity)
        item_vals = self.tree.item(selected[0], 'values')
        if not item_vals:
            messagebox.showerror('Error', 'Unable to read selected item')
            return
        item_name = item_vals[0]

        # confirm
        if not messagebox.askyesno('Confirm Delete', f'Delete product "{item_name}" from inventory?'):
            return

        try:
            # delete from DB
            cursor.execute("DELETE FROM inventory WHERE item=%s", (item_name,))
            db.commit()  # persist deletion

            # update in-memory inventory
            if item_name in self.inventory:
                del self.inventory[item_name]

            # remove from Treeview
            self.tree.delete(selected[0])

            # add blockchain transaction
            transaction = {
                'user': self.current_user,
                'action': 'Delete',
                'item': item_name,
                'quantity': 0,
                'timestamp': time.time()
            }
            self.blockchain.add_transaction(transaction)
            previous_block = self.blockchain.get_previous_block()
            previous_nonce = previous_block['nonce']
            nonce = self.blockchain.proof_of_work(previous_nonce)
            previous_hash = self.blockchain.hash(previous_block)
            self.blockchain.create_block(nonce, previous_hash)

            messagebox.showinfo('Deleted', f'Product "{item_name}" deleted successfully')
        except Exception as e:
            db.rollback()
            messagebox.showerror('Error', f'Failed to delete product: {e}')

    def view_blockchain(self):
        if not self.blockchain.chain:
            messagebox.showinfo('Blockchain', 'Blockchain is empty')
            return
        blocks_text = ''
        for block in self.blockchain.chain:
            blocks_text += f"Block {block['index']} - Timestamp: {time.ctime(block['timestamp'])}\n"
            blocks_text += f"Previous Hash: {block['previous_hash']}\n"
            blocks_text += f"Nonce: {block['nonce']}\n"
            blocks_text += "Transactions:\n"
            for tx in block['transactions']:
                blocks_text += f"- User: {tx['user']}, Action: {tx['action']}, Item: {tx['item']}, Quantity: {tx['quantity']}, Time: {time.ctime(tx['timestamp'])}\n"
            blocks_text += '\n'
        blockchain_window = Toplevel(self.root)
        blockchain_window.title('Blockchain Ledger')
        txt = Text(blockchain_window, wrap=WORD, width=80, height=30)
        txt.insert(END, blocks_text)
        txt.config(state=DISABLED)
        txt.pack()

if __name__ == '__main__':
    root = Tk()
    app = InventorySystem(root)
    root.mainloop()