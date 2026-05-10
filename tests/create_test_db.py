"""Test database creation for SQLime verification."""
import sqlite3, os

db = 'test_forensic.db'
if os.path.exists(db):
    os.remove(db)

conn = sqlite3.connect(db)
conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, avatar BLOB)')
conn.execute('CREATE TABLE logs (id INTEGER PRIMARY KEY, action TEXT, ts TIMESTAMP)')
conn.execute('CREATE INDEX idx_email ON users(email)')

# Insert data
conn.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com', NULL)")
conn.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com', NULL)")
conn.execute("INSERT INTO users VALUES (3, 'Charlie', 'charlie@example.com', NULL)")
conn.execute("INSERT INTO logs VALUES (1, 'login', '2024-01-01')")
conn.execute("INSERT INTO logs VALUES (2, 'logout', '2024-01-02')")
conn.commit()

# Delete a row (for recovery testing)
conn.execute("DELETE FROM users WHERE id = 2")
conn.commit()
conn.close()
print('Test DB created successfully')
