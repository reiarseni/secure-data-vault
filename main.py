import sys
import os
import sqlite3
import secrets
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QDialog, QVBoxLayout, QHBoxLayout,
    QLineEdit, QLabel, QPushButton, QMessageBox, QTableView, QWidget, QInputDialog
)
from PyQt5.QtCore import Qt, QSortFilterProxyModel
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512


# ------------------ Encryption Utilities ------------------

def encrypt_data(plain_text: bytes, key: bytes) -> (bytes, bytes, bytes):
    """
    Encrypts plain_text using AES-256-GCM.
    Returns (nonce, tag, ciphertext).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text)
    return cipher.nonce, tag, ciphertext


def decrypt_data(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-256-GCM with given nonce and tag.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_title(title: str, key: bytes) -> bytes:
    """
    Encrypts a title string.
    The returned blob = nonce (12 bytes) + tag (16 bytes) + ciphertext.
    """
    data = title.encode('utf-8')
    nonce, tag, ciphertext = encrypt_data(data, key)
    return nonce + tag + ciphertext


def decrypt_title(blob: bytes, key: bytes) -> str:
    """
    Decrypts the blob to retrieve the plain title.
    Expects blob formatted as nonce (12) + tag (16) + ciphertext.
    """
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    return decrypt_data(nonce, tag, ciphertext, key).decode('utf-8')


# ------------------ Database Setup Utility ------------------

def create_tables(conn):
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS hash (id INTEGER PRIMARY KEY AUTOINCREMENT, password_hash TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS title (key TEXT PRIMARY KEY, title BLOB)")
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS value_key (key TEXT PRIMARY KEY, content BLOB, nonce BLOB, etiqueta BLOB)")
    conn.commit()


def master_key_exists(db_path: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM hash")
        count = cur.fetchone()[0]
        return count > 0
    except Exception:
        return False
    finally:
        conn.close()


# ------------------ Data Manager ------------------

class DataManager:
    def __init__(self, db_path: str, master_key: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        # Using a static salt for demonstration purposes only.
        self.SALT = b'static_salt'
        # Derive encryption key using PBKDF2 (in production, consider using Argon2id)
        self.master_key_bytes = master_key.encode('utf-8')
        self.encryption_key = PBKDF2(self.master_key_bytes, self.SALT, dkLen=32, count=100000, hmac_hash_module=SHA512)
        if not self.verify_master_key():
            raise ValueError("Master key verification failed.")

    def verify_master_key(self) -> bool:
        """
        Verifies the provided master key against the stored hash in 'hash'.
        If no master key exists, an error is raised.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT password_hash FROM hash LIMIT 1")
        row = cur.fetchone()
        computed_hash = hashlib.sha256(self.encryption_key).hexdigest()
        if row:
            stored_hash = row[0]
            return computed_hash == stored_hash
        else:
            raise ValueError("No master key set. Please set a new master key.")

    def load_titles(self) -> list:
        """
        Loads all items from 'title', decrypts the titles and returns a list of tuples (key, title).
        """
        cur = self.conn.cursor()
        cur.execute("SELECT key, title FROM title")
        titles = []
        for key, encrypted_blob in cur.fetchall():
            try:
                title_text = decrypt_title(encrypted_blob, self.encryption_key)
            except Exception:
                title_text = "Decryption Error"
            titles.append((key, title_text))
        return titles

    def update_title(self, key: str, new_title: str):
        """
        Updates (re-encrypts) the title for a given key.
        """
        new_encrypted = encrypt_title(new_title, self.encryption_key)
        cur = self.conn.cursor()
        cur.execute("UPDATE title SET title = ? WHERE key = ?", (new_encrypted, key))
        self.conn.commit()

    def add_item(self, title: str, content: str):
        """
        Adds a new item with encrypted title and content.
        Generates a random 50-character key.
        """
        key = secrets.token_hex(25)  # 50 hex characters
        encrypted_title = encrypt_title(title, self.encryption_key)
        cur = self.conn.cursor()
        cur.execute("INSERT INTO title (key, title) VALUES (?, ?)", (key, encrypted_title))
        # Encrypt content separately (nonce, tag, and ciphertext stored separately)
        nonce, tag, ciphertext = encrypt_data(content.encode('utf-8'), self.encryption_key)
        cur.execute(
            "INSERT INTO value_key (key, content, nonce, etiqueta) VALUES (?, ?, ?, ?)",
            (key, ciphertext, nonce, tag)
        )
        self.conn.commit()

    def delete_item(self, key: str):
        """
        Deletes an item (both title and content) from the database.
        """
        cur = self.conn.cursor()
        cur.execute("DELETE FROM value_key WHERE key = ?", (key,))
        cur.execute("DELETE FROM title WHERE key = ?", (key,))
        self.conn.commit()

    def decrypt_content(self, key: str, provided_master_key: str) -> str:
        """
        Decrypts the content for a given key.
        Requires the user to re-enter the master key.
        """
        provided_key = provided_master_key.encode('utf-8')
        derived_key = PBKDF2(provided_key, self.SALT, dkLen=32, count=100000, hmac_hash_module=SHA512)
        computed_hash = hashlib.sha256(derived_key).hexdigest()
        cur = self.conn.cursor()
        cur.execute("SELECT password_hash FROM hash LIMIT 1")
        row = cur.fetchone()
        if row and computed_hash != row[0]:
            raise ValueError("Invalid master key for content decryption.")
        cur.execute("SELECT content, nonce, etiqueta FROM value_key WHERE key = ?", (key,))
        row = cur.fetchone()
        if row:
            ciphertext, nonce, tag = row
            return decrypt_data(nonce, tag, ciphertext, derived_key).decode('utf-8')
        else:
            return ""

    def change_master_key(self, new_master_key: str):
        """
        Changes the master key: decrypts all items with the old key and re-encrypts them with the new key.
        """
        new_key_bytes = new_master_key.encode('utf-8')
        new_encryption_key = PBKDF2(new_key_bytes, self.SALT, dkLen=32, count=100000, hmac_hash_module=SHA512)
        cur = self.conn.cursor()
        # Update titles in 'title'
        cur.execute("SELECT key, title FROM title")
        for key, encrypted_blob in cur.fetchall():
            title_text = decrypt_title(encrypted_blob, self.encryption_key)
            new_encrypted_title = encrypt_title(title_text, new_encryption_key)
            cur.execute("UPDATE title SET title = ? WHERE key = ?", (new_encrypted_title, key))
        # Update contents in 'value_key'
        cur.execute("SELECT key, content, nonce, etiqueta FROM value_key")
        for key, ciphertext, nonce, tag in cur.fetchall():
            content_text = decrypt_data(nonce, tag, ciphertext, self.encryption_key).decode('utf-8')
            new_nonce, new_tag, new_ciphertext = encrypt_data(content_text.encode('utf-8'), new_encryption_key)
            cur.execute(
                "UPDATE value_key SET content = ?, nonce = ?, etiqueta = ? WHERE key = ?",
                (new_ciphertext, new_nonce, new_tag, key)
            )
        # Update the master key hash in 'hash'
        new_hash = hashlib.sha256(new_encryption_key).hexdigest()
        cur.execute("UPDATE hash SET password_hash = ? WHERE id = 1", (new_hash,))
        self.conn.commit()
        # Replace in-memory key (secure deletion pending for production)
        self.master_key_bytes = new_key_bytes
        self.encryption_key = new_encryption_key


# ------------------ PyQt Dialogs and Windows ------------------

class NewMasterPasswordDialog(QDialog):
    def __init__(self, db_path: str):
        super().__init__()
        self.setWindowTitle("Set Initial Master Key")
        self.db_path = db_path
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter new master key:"))
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.key_edit)
        self.set_btn = QPushButton("Set Password")
        self.set_btn.clicked.connect(self.set_password)
        layout.addWidget(self.set_btn)
        self.setLayout(layout)

    def set_password(self):
        new_key = self.key_edit.text()
        if not new_key:
            QMessageBox.warning(self, "Warning", "Master key cannot be empty.")
            return
        try:
            salt = b'static_salt'
            encryption_key = PBKDF2(new_key.encode('utf-8'), salt, dkLen=32, count=100000, hmac_hash_module=SHA512)
            computed_hash = hashlib.sha256(encryption_key).hexdigest()
            conn = sqlite3.connect(self.db_path)
            create_tables(conn)  # Ensure tables exist before inserting
            cur = conn.cursor()
            cur.execute("INSERT INTO hash (password_hash) VALUES (?)", (computed_hash,))
            conn.commit()
            conn.close()
            QMessageBox.information(self, "Success", "Master key set successfully.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to set master key: {str(e)}")


class LoginDialog(QDialog):
    def __init__(self, db_path: str):
        super().__init__()
        self.setWindowTitle("Login")
        self.db_path = db_path
        self.data_manager = None

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter master key:"))
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.key_edit)

        btn_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.attempt_login)
        btn_layout.addWidget(self.login_btn)

        self.change_key_btn = QPushButton("Change Master Key")
        self.change_key_btn.clicked.connect(self.open_change_key)
        btn_layout.addWidget(self.change_key_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def attempt_login(self):
        master_key = self.key_edit.text()
        try:
            self.data_manager = DataManager(self.db_path, master_key)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")

    def open_change_key(self):
        # Allows changing the master key even from the login dialog.
        dlg = ChangeMasterKeyDialog(self.db_path)
        dlg.exec_()


class MainWindow(QMainWindow):
    def __init__(self, data_manager: DataManager):
        super().__init__()
        self.setWindowTitle("Secure Item Manager")
        self.data_manager = data_manager
        self.item_data = {}  # In-memory mapping: key -> title

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        # Search field for live filtering
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search titles...")
        layout.addWidget(self.search_edit)

        # QTableView to show decrypted titles
        self.table_view = QTableView()
        layout.addWidget(self.table_view)

        # Standard model to hold the items
        self.model = QStandardItemModel(0, 2)
        self.model.setHorizontalHeaderLabels(["Key", "Title"])
        self.load_items()
        # Hide key column
        self.table_view.setColumnHidden(0, True)

        # Proxy model for dynamic filtering (case-insensitive)
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterKeyColumn(1)  # Filter on Title column
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.table_view.setModel(self.proxy_model)

        self.search_edit.textChanged.connect(self.proxy_model.setFilterFixedString)
        self.model.itemChanged.connect(self.handle_item_changed)

        # Buttons for actions
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_item)
        btn_layout.addWidget(self.add_btn)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.clicked.connect(self.delete_item)
        btn_layout.addWidget(self.delete_btn)

        self.view_btn = QPushButton("View Content")
        self.view_btn.clicked.connect(self.view_content)
        btn_layout.addWidget(self.view_btn)
        layout.addLayout(btn_layout)

    def load_items(self):
        """
        Loads items from the database into the model.
        """
        self.model.removeRows(0, self.model.rowCount())
        self.item_data = {}
        for key, title_text in self.data_manager.load_titles():
            self.item_data[key] = title_text
            key_item = QStandardItem(key)
            key_item.setEditable(False)
            title_item = QStandardItem(title_text)
            self.model.appendRow([key_item, title_item])
        if not self.item_data:
            # Show message in table if no results
            self.model.appendRow([QStandardItem(""), QStandardItem("No results found")])

    def handle_item_changed(self, item: QStandardItem):
        """
        When editing a title inline, update the database.
        """
        if item.column() == 1:
            # Retrieve the key of the item (column 0 of the same row)
            key = self.model.item(item.row(), 0).text()
            new_title = item.text()
            try:
                self.data_manager.update_title(key, new_title)
                self.item_data[key] = new_title
            except Exception as e:
                QMessageBox.warning(self, "Update Failed", f"Could not update title: {str(e)}")
                # Reload items in case of error
                self.load_items()

    def add_item(self):
        """
        Adds a new item. For simplicity, title and content are requested via QInputDialog.
        """
        title, ok1 = QInputDialog.getText(self, "Add Item", "Enter title:")
        if not ok1 or not title:
            return
        content, ok2 = QInputDialog.getMultiLineText(self, "Add Item", "Enter content:")
        if not ok2:
            return
        try:
            self.data_manager.add_item(title, content)
            self.load_items()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add item: {str(e)}")

    def delete_item(self):
        """
        Deletes the currently selected item.
        """
        indexes = self.table_view.selectionModel().selectedRows()
        if indexes:
            index = indexes[0]
            # Map proxy index to source index
            source_index = self.proxy_model.mapToSource(index)
            key = self.model.item(source_index.row(), 0).text()
            if QMessageBox.question(self, "Confirm Delete",
                                    "Are you sure you want to delete this item?") == QMessageBox.Yes:
                try:
                    self.data_manager.delete_item(key)
                    self.load_items()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete item: {str(e)}")
        else:
            QMessageBox.information(self, "No Selection", "Please select an item to delete.")

    def view_content(self):
        """
        Prompts the user for the master key again to decrypt and show the content.
        """
        indexes = self.table_view.selectionModel().selectedRows()
        if indexes:
            index = indexes[0]
            source_index = self.proxy_model.mapToSource(index)
            key = self.model.item(source_index.row(), 0).text()
            dlg = ContentDialog(self.data_manager, key)
            dlg.exec_()
        else:
            QMessageBox.information(self, "No Selection", "Please select an item to view its content.")


class ContentDialog(QDialog):
    def __init__(self, data_manager: DataManager, key: str):
        super().__init__()
        self.data_manager = data_manager
        self.item_key = key
        self.setWindowTitle("View Content")
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Re-enter master key to decrypt content:"))
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.key_edit)
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_content)
        layout.addWidget(self.decrypt_btn)
        self.content_label = QLabel("")
        layout.addWidget(self.content_label)
        self.setLayout(layout)

    def decrypt_content(self):
        provided_key = self.key_edit.text()
        try:
            content = self.data_manager.decrypt_content(self.item_key, provided_key)
            self.content_label.setText(f"Content:\n{content}")
        except Exception as e:
            QMessageBox.critical(self, "Decryption Failed", f"Could not decrypt content: {str(e)}")


class ChangeMasterKeyDialog(QDialog):
    def __init__(self, db_path: str):
        super().__init__()
        self.setWindowTitle("Change Master Key")
        self.db_path = db_path
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter current master key:"))
        self.current_key_edit = QLineEdit()
        self.current_key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.current_key_edit)
        layout.addWidget(QLabel("Enter new master key:"))
        self.new_key_edit = QLineEdit()
        self.new_key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_key_edit)
        self.change_btn = QPushButton("Change Key")
        self.change_btn.clicked.connect(self.change_key)
        layout.addWidget(self.change_btn)
        self.setLayout(layout)

    def change_key(self):
        current_key = self.current_key_edit.text()
        new_key = self.new_key_edit.text()
        try:
            # First, instantiate DataManager to verify current key
            dm = DataManager(self.db_path, current_key)
            dm.change_master_key(new_key)
            QMessageBox.information(self, "Success", "Master key updated successfully.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change master key: {str(e)}")


class InitializationDialog(QDialog):
    def __init__(self, db_path: str):
        super().__init__()
        self.setWindowTitle("Database Initialization")
        self.db_path = db_path
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter initial master key:"))
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.key_edit)
        self.init_btn = QPushButton("Initialize Database")
        self.init_btn.clicked.connect(self.initialize_db)
        layout.addWidget(self.init_btn)
        self.setLayout(layout)

    def initialize_db(self):
        master_key = self.key_edit.text()
        if not master_key:
            QMessageBox.warning(self, "Warning", "Master key cannot be empty.")
            return
        try:
            conn = sqlite3.connect(self.db_path)
            create_tables(conn)
            conn.close()
            # Instantiate DataManager to trigger master key insertion via verification
            dm = DataManager(self.db_path, master_key)
            QMessageBox.information(self, "Success", "Database initialized successfully.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize database: {str(e)}")


# ------------------ Main Application ------------------

if __name__ == '__main__':
    # It is assumed that the file 'secure_items.db' will be created if it does not exist.
    DB_PATH = "secure_items.db"
    app = QApplication(sys.argv)

    if not os.path.exists(DB_PATH):
        init_dialog = InitializationDialog(DB_PATH)
        if init_dialog.exec_() != QDialog.Accepted:
            sys.exit(0)

    # Ensure the database has the required tables even if the file exists but is empty
    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)
    conn.close()

    # Check if a master key is set in the database; if not, prompt for a new master key.
    if not master_key_exists(DB_PATH):
        new_key_dialog = NewMasterPasswordDialog(DB_PATH)
        if new_key_dialog.exec_() != QDialog.Accepted:
            sys.exit(0)

    login = LoginDialog(DB_PATH)
    if login.exec_() == QDialog.Accepted:
        main_window = MainWindow(login.data_manager)
        main_window.show()
        sys.exit(app.exec_())
