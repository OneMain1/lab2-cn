#!/usr/bin/env python3
"""
Key Management and Authentication System
"""

import os
import json
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt
import logging

class KeyManager:
    def __init__(self, keys_dir='keys', jwt_secret=None):
        self.keys_dir = keys_dir
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.private_key = None
        self.public_key = None
        self.users_db = {}
        self.active_tokens = {}
        
        # Ensure keys directory exists
        os.makedirs(keys_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize or load keys
        self.initialize_keys()
        self.load_users_db()
    
    def initialize_keys(self):
        """Initialize or load RSA key pair"""
        private_key_path = os.path.join(self.keys_dir, 'private_key.pem')
        public_key_path = os.path.join(self.keys_dir, 'public_key.pem')
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            self.load_keys()
        else:
            self.generate_keys()
    
    def generate_keys(self):
        """Generate new RSA key pair"""
        self.logger.info("Generating new RSA key pair...")
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get public key
        self.public_key = self.private_key.public_key()
        
        # Save keys
        self.save_keys()
        self.logger.info("RSA key pair generated and saved")
    
    def save_keys(self):
        """Save RSA keys to files"""
        private_key_path = os.path.join(self.keys_dir, 'private_key.pem')
        public_key_path = os.path.join(self.keys_dir, 'public_key.pem')
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        # Set appropriate permissions
        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)
    
    def load_keys(self):
        """Load RSA keys from files"""
        private_key_path = os.path.join(self.keys_dir, 'private_key.pem')
        public_key_path = os.path.join(self.keys_dir, 'public_key.pem')
        
        try:
            with open(private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            self.logger.info("RSA keys loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading keys: {e}")
            self.generate_keys()
    
    def load_users_db(self):
        """Load users database"""
        users_db_path = os.path.join(self.keys_dir, 'users.json')
        
        try:
            if os.path.exists(users_db_path):
                with open(users_db_path, 'r') as f:
                    self.users_db = json.load(f)
                self.logger.info("Users database loaded")
            else:
                self.create_default_admin()
        except Exception as e:
            self.logger.error(f"Error loading users database: {e}")
            self.create_default_admin()
    
    def save_users_db(self):
        """Save users database"""
        users_db_path = os.path.join(self.keys_dir, 'users.json')
        
        try:
            with open(users_db_path, 'w') as f:
                json.dump(self.users_db, f, indent=2)
            self.logger.info("Users database saved")
        except Exception as e:
            self.logger.error(f"Error saving users database: {e}")
    
    def create_default_admin(self):
        """Create default admin user"""
        admin_password = secrets.token_urlsafe(16)
        self.create_user('admin', admin_password, role='admin')
        
        # Save admin credentials to file
        admin_creds_path = os.path.join(self.keys_dir, 'admin_credentials.txt')
        with open(admin_creds_path, 'w') as f:
            f.write(f"Default Admin Credentials:\n")
            f.write(f"Username: admin\n")
            f.write(f"Password: {admin_password}\n")
            f.write(f"Created: {datetime.now().isoformat()}\n")
        
        os.chmod(admin_creds_path, 0o600)
        self.logger.info(f"Default admin user created. Credentials saved to {admin_creds_path}")
    
    def hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_bytes(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return base64.b64encode(salt + pwdhash).decode('utf-8')
    
    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        try:
            decoded_hash = base64.b64decode(stored_hash.encode('utf-8'))
            salt = decoded_hash[:32]
            stored_pwdhash = decoded_hash[32:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            return pwdhash == stored_pwdhash
        except Exception:
            return False
    
    def create_user(self, username, password, role='user', expires_days=30):
        """Create a new user"""
        if username in self.users_db:
            raise ValueError(f"User {username} already exists")
        
        expires_at = datetime.now() + timedelta(days=expires_days)
        
        self.users_db[username] = {
            'password_hash': self.hash_password(password),
            'role': role,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat(),
            'active': True
        }
        
        self.save_users_db()
        self.logger.info(f"User {username} created with role {role}")
        return True
    
    def authenticate_user(self, username, password):
        """Authenticate user"""
        if username not in self.users_db:
            return False
        
        user = self.users_db[username]
        
        # Check if user is active
        if not user.get('active', False):
            return False
        
        # Check if user has expired
        expires_at = datetime.fromisoformat(user['expires_at'])
        if datetime.now() > expires_at:
            self.logger.warning(f"User {username} has expired")
            return False
        
        # Verify password
        return self.verify_password(password, user['password_hash'])
    
    def generate_jwt_token(self, username, expires_hours=24):
        """Generate JWT token for authenticated user"""
        if username not in self.users_db:
            raise ValueError(f"User {username} not found")
        
        user = self.users_db[username]
        expires_at = datetime.now() + timedelta(hours=expires_hours)
        
        payload = {
            'username': username,
            'role': user['role'],
            'exp': expires_at.timestamp(),
            'iat': datetime.now().timestamp()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        
        # Store active token
        self.active_tokens[token] = {
            'username': username,
            'expires_at': expires_at.isoformat()
        }
        
        return token
    
    def verify_jwt_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            username = payload['username']
            
            # Check if token is in active tokens
            if token not in self.active_tokens:
                return None
            
            # Check if user still exists and is active
            if username not in self.users_db or not self.users_db[username].get('active', False):
                self.revoke_token(token)
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            self.revoke_token(token)
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token):
        """Revoke a JWT token"""
        if token in self.active_tokens:
            del self.active_tokens[token]
            self.logger.info("Token revoked")
    
    def encrypt_data(self, data):
        """Encrypt data using RSA public key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using RSA private key"""
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        decrypted = self.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
    
    def get_public_key_pem(self):
        """Get public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def list_users(self):
        """List all users"""
        users_info = []
        for username, user_data in self.users_db.items():
            users_info.append({
                'username': username,
                'role': user_data['role'],
                'created_at': user_data['created_at'],
                'expires_at': user_data['expires_at'],
                'active': user_data['active']
            })
        return users_info
    
    def update_user_expiry(self, username, expires_days):
        """Update user expiry"""
        if username not in self.users_db:
            raise ValueError(f"User {username} not found")
        
        expires_at = datetime.now() + timedelta(days=expires_days)
        self.users_db[username]['expires_at'] = expires_at.isoformat()
        self.save_users_db()
        
        self.logger.info(f"Updated expiry for user {username}")
        return True
    
    def deactivate_user(self, username):
        """Deactivate user"""
        if username not in self.users_db:
            raise ValueError(f"User {username} not found")
        
        self.users_db[username]['active'] = False
        self.save_users_db()
        
        # Revoke all tokens for this user
        tokens_to_revoke = [token for token, data in self.active_tokens.items() 
                           if data['username'] == username]
        for token in tokens_to_revoke:
            self.revoke_token(token)
        
        self.logger.info(f"User {username} deactivated")
        return True

if __name__ == "__main__":
    # Command line interface for key management
    import argparse
    
    parser = argparse.ArgumentParser(description='Key Management System')
    parser.add_argument('action', choices=['generate', 'create-user', 'list-users', 'test-auth'])
    parser.add_argument('--username', help='Username for user operations')
    parser.add_argument('--password', help='Password for user operations')
    parser.add_argument('--role', default='user', choices=['user', 'admin'], help='User role')
    parser.add_argument('--expires-days', type=int, default=30, help='User expiry in days')
    
    args = parser.parse_args()
    
    km = KeyManager()
    
    if args.action == 'generate':
        km.generate_keys()
        print("New keys generated")
    
    elif args.action == 'create-user':
        if not args.username or not args.password:
            print("Username and password required")
            exit(1)
        
        try:
            km.create_user(args.username, args.password, args.role, args.expires_days)
            print(f"User {args.username} created successfully")
        except ValueError as e:
            print(f"Error: {e}")
    
    elif args.action == 'list-users':
        users = km.list_users()
        print("\nUsers:")
        for user in users:
            status = "Active" if user['active'] else "Inactive"
            print(f"  {user['username']} ({user['role']}) - {status} - Expires: {user['expires_at']}")
    
    elif args.action == 'test-auth':
        if not args.username or not args.password:
            print("Username and password required")
            exit(1)
        
        if km.authenticate_user(args.username, args.password):
            token = km.generate_jwt_token(args.username)
            print(f"Authentication successful. Token: {token}")
        else:
            print("Authentication failed")
