import sqlite3
import argparse
import re
import secrets
import hashlib
import os

DATABASE = 'songs.db'

def generate_password_hash(password):
    """Gera um hash da senha usando SHA-256 com salt"""
    salt = os.urandom(32)
    hash_obj = hashlib.sha256()
    hash_obj.update(salt + password.encode('utf-8'))
    return f"sha256${salt.hex()}${hash_obj.hexdigest()}"

def validate_password(password):
    """Valida a força da senha"""
    if len(password) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "A senha deve conter pelo menos uma letra maiúscula"
    if not re.search(r'[a-z]', password):
        return False, "A senha deve conter pelo menos uma letra minúscula"
    if not re.search(r'\d', password):
        return False, "A senha deve conter pelo menos um número"
    return True, "Senha válida"

def validate_username(username):
    """Valida o nome de usuário"""
    if not username or len(username) < 3:
        return False, "O nome de usuário deve ter pelo menos 3 caracteres"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "O nome de usuário deve conter apenas letras, números e underscore"
    return True, "Nome de usuário válido"

def create_user(username, password):
    """Cria um novo usuário no banco de dados com senha criptografada."""
    
    # Validações
    is_valid_username, username_error = validate_username(username)
    if not is_valid_username:
        print(f"❌ Erro: {username_error}")
        return False
    
    is_valid_password, password_error = validate_password(password)
    if not is_valid_password:
        print(f"❌ Erro: {password_error}")
        return False
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Garante que a tabela de usuários exista
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        
        # Cria o hash da senha
        password_hash = generate_password_hash(password)
        
        # Insere o novo usuário
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        
        conn.commit()
        print(f"✅ Usuário '{username}' criado com sucesso!")
        return True

    except sqlite3.IntegrityError:
        print(f"❌ Erro: O usuário '{username}' já existe.")
        return False
    except Exception as e:
        print(f"❌ Ocorreu um erro: {e}")
        return False
    finally:
        if conn:
            conn.close()

def generate_secure_password():
    """Gera uma senha segura aleatória"""
    # Gera uma senha com pelo menos 12 caracteres
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    password = ''.join(secrets.choice(chars) for _ in range(12))
    return password

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cria um novo usuário para o ChordChart Pro (Standalone).")
    parser.add_argument("username", type=str, help="O nome de usuário a ser criado.")
    parser.add_argument("password", type=str, nargs='?', help="A senha para o novo usuário. Se não fornecida, será gerada automaticamente.")
    parser.add_argument("--generate-password", action="store_true", help="Gera uma senha segura automaticamente.")
    
    args = parser.parse_args()
    
    if args.generate_password or not args.password:
        password = generate_secure_password()
        print(f"🔐 Senha gerada automaticamente: {password}")
        print("⚠️  IMPORTANTE: Salve esta senha em um local seguro!")
    else:
        password = args.password
    
    create_user(args.username, password) 