"""Authentication service — bcrypt + SQLite user management."""
import os
import sqlite3
import logging
from datetime import datetime, timezone
import bcrypt
from flask_login import UserMixin

log = logging.getLogger(__name__)

DB_PATH = os.getenv('PORTAL_DB_PATH', '/opt/fasterup-portal/data/portal.db')


def get_db():
    """Returns a fresh SQLite connection. Caller is responsible for closing."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


class User(UserMixin):
    """User model compatible with flask-login."""
    def __init__(self, row):
        self.id = row['id']
        self.username = row['username']
        self.role = row['role']
        self.organization = row['organization']
        self.must_change_password = bool(row['must_change_password'])
        self.is_active_flag = bool(row['active'])

    @property
    def is_active(self):
        return self.is_active_flag

    def get_id(self):
        return str(self.id)

    @property
    def is_supervisor(self):
        return self.role == 'supervisor'

    @property
    def is_analyst(self):
        return self.role == 'analyst'

    @property
    def can_see_all_orgs(self):
        return self.organization in ("ALL", "FASTERUP_DIRECT")

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'organization': self.organization,
            'must_change_password': self.must_change_password,
        }


def get_user_by_id(user_id):
    conn = get_db()
    try:
        row = conn.execute(
            'SELECT * FROM users WHERE id = ? AND active = 1',
            (user_id,)
        ).fetchone()
        return User(row) if row else None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db()
    try:
        row = conn.execute(
            'SELECT * FROM users WHERE username = ? AND active = 1',
            (username,)
        ).fetchone()
        return (User(row), row['password_hash']) if row else (None, None)
    finally:
        conn.close()


def verify_password(plain, password_hash):
    """Returns True if plain matches the bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        log.error(f'bcrypt verify failed: {e}')
        return False


def hash_password(plain):
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def update_password(user_id, new_password):
    """Update password and clear must_change_password flag."""
    new_hash = hash_password(new_password)
    conn = get_db()
    try:
        conn.execute(
            'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
            (new_hash, user_id)
        )
        conn.commit()
        log.info(f'Password updated for user_id={user_id}')
        return True
    except Exception as e:
        log.error(f'update_password failed: {e}')
        return False
    finally:
        conn.close()


def update_last_login(user_id):
    conn = get_db()
    try:
        conn.execute(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now(timezone.utc).isoformat(), user_id)
        )
        conn.commit()
    finally:
        conn.close()
