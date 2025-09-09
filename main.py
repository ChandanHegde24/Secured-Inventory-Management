import hashlib
import json
import time
from tkinter import *
from tkinter import messagebox, ttk

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_block(nonce=1, previous_hash='0')

    def create_block(self, nonce, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'nonce': nonce,
            'previous_hash': previous_hash,
            'transactions': self.pending_transactions
        }
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

# Sample role-based users
users = {
    'admin': '1234',  # user: PIN
    'manager': '5678',
    'staff': '0000'
}

class InventorySystem:
    def __init__(self, root):
        self.root = root
        self.root.title('Multi-Branch Inventory Management')
        self.blockchain = Blockchain()
        self.inventory = {}
        self.current_user = None
        self.login_screen()

    def login_screen(self):
        self.clear_root()
        Label(self.root, text='Login', font=('Arial', 18)).pack(pady=10)
        Label(self.root, text='User ID').pack()
        self.user_entry = Entry(self.root)
        self.user_entry.pack()
        Label(self.root, text='PIN').pack()
        self.pin_entry = Entry(self.root, show='*')
        self.pin_entry.pack()
        Button(self.root, text='Login', command=self.login).pack(pady=10)

    def login(self):
        user = self.user_entry.get()
        pin = self.pin_entry.get()
        if user in users and users[user] == pin:
            self.current_user = user
            self.main_screen()
        else:
            messagebox.showerror('Login Failed', 'Invalid user ID or PIN')

    def main_screen(self):
        self.clear_root()
        Label(self.root, text=f'Welcome {self.current_user}', font=('Arial', 16)).pack(pady=10)

        # Inventory display
        self.tree = ttk.Treeview(self.root, columns=('Item', 'Quantity'), show='headings')
        self.tree.heading('Item', text='Item')
        self.tree.heading('Quantity', text='Quantity')
        self.tree.pack(pady=10)
        self.load_inventory()

        # Controls
        frame = Frame(self.root)
        frame.pack(pady=10)
        Label(frame, text='Item Name').grid(row=0, column=0)
        self.item_entry = Entry(frame)
        self.item_entry.grid(row=0, column=1)
        Label(frame, text='Quantity').grid(row=1, column=0)
        self.qty_entry = Entry(frame)
        self.qty_entry.grid(row=1, column=1)
        Button(frame, text='Add/Update Stock', command=self.add_update_stock).grid(row=2, column=0, columnspan=2, pady=5)

        Button(self.root, text='View Blockchain', command=self.view_blockchain).pack(pady=5)
        Button(self.root, text='Logout', command=self.login_screen).pack(pady=5)

    def load_inventory(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for item, qty in self.inventory.items():
            self.tree.insert('', END, values=(item, qty))

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
        self.inventory[item] = prev_qty + qty

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

        self.load_inventory()
        messagebox.showinfo('Success', f'Stock for {item} updated by {qty}')

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

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == '__main__':
    root = Tk()
    app = InventorySystem(root)
    root.mainloop()