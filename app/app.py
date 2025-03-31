#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import sqlite3
import os
import logging
import bcrypt
from validator_collection import is_email, is_string

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users")
    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    
    # SECURITY ISSUE: No input validation
    username = data.get('username')
    password = data.get('password')  # SECURITY ISSUE: Password stored in plaintext
    hash_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    email = data.get('email')
    if is_string(username, minimum_length=3, maximum_length=20) == False:
        raise Exception("Invalid username string pattern.")
    if is_email(email) == False:
        raise Exception("Invalid email pattern.")
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        # SECURITY ISSUE: SQL Injection vulnerability
        query = "INSERT INTO users (username, password, email) VALUES ('?', '?', '?')"
        cursor.execute(query, (username, hash_password, email))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        conn.close()

@app.route('/api/search', methods=['GET'])
def search_users():
    # SECURITY ISSUE: Reflected parameter
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SECURITY ISSUE: SQL Injection vulnerability
    cursor.execute("SELECT id, username, email FROM users WHERE username LIKE ?", (f"%{query}%",))
    
    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(users)

if __name__ == '__main__':
    init_db()
    # SECURITY ISSUE: Debug mode enabled
    debug_mode = os.environ.get("DEBUG", "False") == True
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)), debug=debug_mode)
