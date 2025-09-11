import os
import sqlite3
import unicodedata
import re
import logging
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import time
from collections import defaultdict

app = Flask(__name__)

# Configurar logging de segurança
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

# Configuração de segurança melhorada
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Gera uma chave segura se não estiver configurada
    import secrets
    SECRET_KEY = secrets.token_hex(32)
    print("⚠️  AVISO: SECRET_KEY não configurada. Gerando chave temporária.")

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hora

CORS(app, supports_credentials=True, origins=os.environ.get('ALLOWED_ORIGINS', '*').split(','))

# Rate limiting simples
login_attempts = defaultdict(list)
invite_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
MAX_INVITE_ATTEMPTS = 10  # Máximo 10 convites por IP por hora
LOGIN_TIMEOUT = 300  # 5 minutos
INVITE_TIMEOUT = 3600  # 1 hora

def is_rate_limited(ip):
    """Verifica se o IP está limitado por tentativas de login"""
    now = time.time()
    # Remove tentativas antigas
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOGIN_TIMEOUT]
    return len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def add_login_attempt(ip):
    """Adiciona uma tentativa de login para o IP"""
    login_attempts[ip].append(time.time())

def is_invite_rate_limited(ip):
    """Verifica se o IP está limitado por tentativas de convite"""
    now = time.time()
    # Remove tentativas antigas
    invite_attempts[ip] = [t for t in invite_attempts[ip] if now - t < INVITE_TIMEOUT]
    return len(invite_attempts[ip]) >= MAX_INVITE_ATTEMPTS

def add_invite_attempt(ip):
    """Adiciona uma tentativa de convite para o IP"""
    invite_attempts[ip].append(time.time())

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

def add_security_headers(response):
    """Adiciona headers de segurança à resposta"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

app.after_request(add_security_headers)

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = 'songs.db'

class User(UserMixin):
    def __init__(self, id, username, name=None, email=None):
        self.id = id
        self.username = username
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute("SELECT id, username, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if user_data:
        return User(
            id=user_data['id'], 
            username=user_data['username'],
            name=user_data['name'],
            email=user_data['email']
        )
    return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        
        # Primeiro, criar as tabelas se não existirem
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password_hash TEXT NOT NULL,
                name TEXT,
                email TEXT,
                user_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                content TEXT NOT NULL, original_key TEXT, user_id INTEGER, is_public BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
            )''')
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                is_public BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlist_songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setlist_id INTEGER NOT NULL,
                song_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                FOREIGN KEY(setlist_id) REFERENCES setlists(id) ON DELETE CASCADE,
                FOREIGN KEY(song_id) REFERENCES songs(id) ON DELETE CASCADE
            )''')
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlist_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setlist_id INTEGER NOT NULL,
                inviter_id INTEGER NOT NULL,
                invited_user_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                accepted_at TIMESTAMP,
                FOREIGN KEY(setlist_id) REFERENCES setlists(id) ON DELETE CASCADE,
                FOREIGN KEY(inviter_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(setlist_id, invited_user_id)
            )''')
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlist_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setlist_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission_type TEXT NOT NULL DEFAULT 'view_only',
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(setlist_id) REFERENCES setlists(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(setlist_id, user_id)
            )''')
        
        # Depois, verificar se as colunas existem e adicionar se necessário
        try:
            # Verificar e adicionar colunas na tabela users
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [column['name'] for column in cursor.fetchall()]
            if 'name' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
            if 'email' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
            if 'user_id' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN user_id TEXT UNIQUE")
            if 'created_at' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                
            # Gerar user_id para usuários existentes que não têm
            cursor.execute("SELECT id FROM users WHERE user_id IS NULL")
            users_without_id = cursor.fetchall()
            for user in users_without_id:
                import secrets
                user_id = secrets.token_urlsafe(8)
                # Garantir que o user_id é único
                while cursor.execute("SELECT id FROM users WHERE user_id = ?", (user_id,)).fetchone():
                    user_id = secrets.token_urlsafe(8)
                cursor.execute("UPDATE users SET user_id = ? WHERE id = ?", (user_id, user['id']))
            
            # Verificar e adicionar colunas na tabela songs
            cursor.execute("PRAGMA table_info(songs)")
            columns = [column['name'] for column in cursor.fetchall()]
            if 'user_id' not in columns:
                cursor.execute("ALTER TABLE songs ADD COLUMN user_id INTEGER REFERENCES users(id)")
            if 'is_public' not in columns:
                cursor.execute("ALTER TABLE songs ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0")
            if 'capo_position' not in columns:
                cursor.execute("ALTER TABLE songs ADD COLUMN capo_position INTEGER NOT NULL DEFAULT 0")
            if 'duration' not in columns:
                cursor.execute("ALTER TABLE songs ADD COLUMN duration TEXT")
            if 'bpm' not in columns:
                cursor.execute("ALTER TABLE songs ADD COLUMN bpm INTEGER")
        except Exception as e:
            print(f"Aviso: {e}")
            
        conn.commit()
        conn.close()

# --- AUTH & USER MANAGEMENT ROUTES ---
@app.route('/api/login', methods=['POST'])
def login():
    # Rate limiting
    client_ip = request.remote_addr
    if is_rate_limited(client_ip):
        return jsonify({"error": "Muitas tentativas de login. Tente novamente em 5 minutos."}), 429
    
    data = request.get_json()
    if not data:
        add_login_attempt(client_ip)
        return jsonify({"error": "Dados inválidos"}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validação básica
    if not username or not password:
        add_login_attempt(client_ip)
        return jsonify({"error": "Usuário e senha são obrigatórios"}), 400
    
    # Validação de entrada
    if len(username) > 50 or len(password) > 100:
        add_login_attempt(client_ip)
        return jsonify({"error": "Dados de entrada muito longos"}), 400
    
    db = get_db()
    try:
        user_data = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(id=user_data['id'], username=user_data['username'])
            login_user(user, remember=False)  # Não usar remember=True por segurança
            session.permanent = True
            # Limpa tentativas de login bem-sucedidas
            if client_ip in login_attempts:
                del login_attempts[client_ip]
            return jsonify({"user": {"username": user.username, "is_admin": user.username == 'admin'}})
        else:
            add_login_attempt(client_ip)
            return jsonify({"error": "Credenciais inválidas"}), 401
    except Exception as e:
        add_login_attempt(client_ip)
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        db.close()

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({"is_logged_in": True, "user": {"username": current_user.username, "is_admin": current_user.username == 'admin'}})
    return jsonify({"is_logged_in": False})

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if current_user.username != 'admin': 
        return jsonify({"error": "Acesso não autorizado"}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Dados inválidos"}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validação de username
    is_valid_username, username_error = validate_username(username)
    if not is_valid_username:
        return jsonify({"error": username_error}), 400
    
    # Validação de senha
    is_valid_password, password_error = validate_password(password)
    if not is_valid_password:
        return jsonify({"error": password_error}), 400
    
    # Validação de tamanho
    if len(username) > 50 or len(password) > 100:
        return jsonify({"error": "Dados de entrada muito longos"}), 400
    
    password_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return jsonify({"message": f"Usuário '{username}' criado com sucesso!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"O usuário '{username}' já existe."}), 409
    except Exception as e:
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username ASC').fetchall()
    db.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    conn = get_db()
    user_to_delete = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['username'] == 'admin': return jsonify({"error": "Não é permitido deletar o usuário administrador"}), 403
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Usuário deletado com sucesso'})

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Dados inválidos"}), 400
    
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    # Validação básica
    if not old_password or not new_password:
        return jsonify({"error": "Senha antiga e nova senha são obrigatórias"}), 400
    
    # Validação de tamanho
    if len(old_password) > 100 or len(new_password) > 100:
        return jsonify({"error": "Senhas muito longas"}), 400
    
    # Validação da nova senha
    is_valid_password, password_error = validate_password(new_password)
    if not is_valid_password:
        return jsonify({"error": password_error}), 400
    
    # Verificar se a nova senha é diferente da antiga
    if old_password == new_password:
        return jsonify({"error": "A nova senha deve ser diferente da senha atual"}), 400
    
    conn = get_db()
    try:
        user_data = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,)).fetchone()
        if not user_data:
            return jsonify({"error": "Usuário não encontrado"}), 404
            
        if not check_password_hash(user_data['password_hash'], old_password):
            return jsonify({"error": "Senha antiga incorreta"}), 401
        
        new_password_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, current_user.id))
        conn.commit()
        return jsonify({"message": "Senha alterada com sucesso"})
    except Exception as e:
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        conn.close()

# --- SONGS API ROUTES ---
@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs_filtered():
    filter_type = request.args.get('filter', 'my_songs')
    db = get_db()
    
    if filter_type == 'public':
        songs_from_db = db.execute('SELECT id, title, original_key, capo_position, duration, bpm FROM songs WHERE is_public = 1').fetchall()
    else:
        songs_from_db = db.execute('SELECT id, title, original_key, capo_position, duration, bpm FROM songs WHERE user_id = ?', (current_user.id,)).fetchall()
    db.close()
    
    songs_list = [dict(song) for song in songs_from_db]

    def normalize_for_sort(text):
        return unicodedata.normalize('NFD', text.lower()).encode('ascii', 'ignore').decode('utf-8')

    songs_list.sort(key=lambda song: normalize_for_sort(song['title']))
    
    return jsonify(songs_list)

@app.route('/api/songs', methods=['POST'])
@login_required
def add_song():
    data = request.get_json()
    conn = get_db()
    conn.execute('INSERT INTO songs (title, content, original_key, user_id, is_public, capo_position, duration, bpm) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                   (data.get('title'), data.get('content'), data.get('original_key'), current_user.id, data.get('is_public', False), data.get('capo_position', 0), data.get('duration'), data.get('bpm')))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música salva com sucesso!"}), 201

@app.route('/api/songs/<int:song_id>', methods=['DELETE'])
@login_required
def delete_song(song_id):
    conn = get_db()
    song = conn.execute("SELECT user_id FROM songs WHERE id = ?", (song_id,)).fetchone()
    if song is None:
        conn.close()
        return jsonify({"error": "Música não encontrada"}), 404
    if song['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para deletar esta música"}), 403
    
    conn.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Música deletada com sucesso'})

@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    song = db.execute('SELECT title, content, capo_position, duration, bpm, original_key FROM songs WHERE id = ?', (song_id,)).fetchone()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

@app.route('/api/songs/<int:song_id>', methods=['PUT'])
@login_required
def update_song(song_id):
    data = request.get_json()
    conn = get_db()
    
    # Verifica se a música existe e pertence ao usuário
    song = conn.execute("SELECT user_id FROM songs WHERE id = ?", (song_id,)).fetchone()
    if song is None:
        conn.close()
        return jsonify({"error": "Música não encontrada"}), 404
    if song['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar esta música"}), 403
    
    # Atualiza a música
    conn.execute('''
        UPDATE songs 
        SET title = ?, content = ?, original_key = ?, duration = ?, bpm = ?, 
            is_public = ?, capo_position = ?
        WHERE id = ?
    ''', (
        data.get('title'), data.get('content'), data.get('original_key'),
        data.get('duration'), data.get('bpm'), data.get('is_public', False),
        data.get('capo_position', 0), song_id
    ))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música atualizada com sucesso!"})

# --- SETLISTS API ROUTES ---
@app.route('/api/setlists', methods=['POST'])
@login_required
def create_setlist():
    data = request.get_json()
    name = data.get('name')
    is_public = data.get('is_public', False)

    if not name or not name.strip():
        return jsonify({"error": "O nome do setlist é obrigatório."}), 400

    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO setlists (name, user_id, is_public) VALUES (?, ?, ?)',
        (name, current_user.id, is_public)
    )
    conn.commit()
    new_setlist_id = cursor.lastrowid
    conn.close()

    return jsonify({"message": "Setlist criado com sucesso!", "setlist": {"id": new_setlist_id, "name": name, "is_public": is_public}}), 201

@app.route('/api/setlists', methods=['GET'])
@login_required
def get_setlists():
    filter_type = request.args.get('filter', 'my_setlists')
    db = get_db()

    if filter_type == 'public':
        setlists_from_db = db.execute('SELECT id, name FROM setlists WHERE is_public = 1 ORDER BY name COLLATE NOCASE ASC').fetchall()
    elif filter_type == 'shared':
        # Setlists compartilhados comigo
        setlists_from_db = db.execute('''
            SELECT DISTINCT s.id, s.name, u.username as owner_username
            FROM setlists s
            JOIN setlist_permissions sp ON s.id = sp.setlist_id
            JOIN users u ON s.user_id = u.id
            WHERE sp.user_id = ?
            ORDER BY s.name COLLATE NOCASE ASC
        ''', (current_user.id,)).fetchall()
    else: 
        setlists_from_db = db.execute('SELECT id, name FROM setlists WHERE user_id = ? ORDER BY name COLLATE NOCASE ASC', (current_user.id,)).fetchall()
    
    db.close()
    return jsonify([dict(s) for s in setlists_from_db])

@app.route('/api/setlists/<int:setlist_id>', methods=['GET'])
@login_required
def get_setlist_details(setlist_id):
    db = get_db()
    
    setlist = db.execute(
        'SELECT id, name, user_id, is_public FROM setlists WHERE id = ?',
        (setlist_id,)
    ).fetchone()

    if not setlist:
        db.close()
        return jsonify({"error": "Setlist não encontrado."}), 404

    is_owner = setlist['user_id'] == current_user.id
    has_permission = False
    permission_type = None
    
    # Verificar se o usuário tem permissão através de convite aceito
    if not is_owner:
        permission = db.execute(
            'SELECT permission_type FROM setlist_permissions WHERE setlist_id = ? AND user_id = ?',
            (setlist_id, current_user.id)
        ).fetchone()
        
        if permission:
            has_permission = True
            permission_type = permission['permission_type']
    
    # Verificar acesso: dono, público ou com permissão
    if not is_owner and not setlist['is_public'] and not has_permission:
        db.close()
        return jsonify({"error": "Acesso não autorizado."}), 403

    songs_in_setlist = db.execute(
        '''
        SELECT s.id, s.title, s.original_key, s.capo_position, s.duration, s.bpm
        FROM songs s
        JOIN setlist_songs ss ON s.id = ss.song_id
        WHERE ss.setlist_id = ?
        ORDER BY ss.position ASC
        ''',
        (setlist_id,)
    ).fetchall()
    
    db.close()

    # Verificar se tem permissão de edição
    can_edit = is_owner
    if not is_owner and has_permission:
        can_edit = permission_type == 'edit'
    
    response_data = {
        "id": setlist['id'],
        "name": setlist['name'],
        "is_public": setlist['is_public'],
        "is_owner": is_owner,
        "has_permission": has_permission,
        "permission_type": permission_type,
        "can_edit": can_edit,  # Dono ou usuário com permissão de edição
        "songs": [dict(song) for song in songs_in_setlist]
    }
    
    return jsonify(response_data)

@app.route('/api/setlists/<int:setlist_id>', methods=['DELETE'])
@login_required
def delete_setlist(setlist_id):
    """Deleta um setlist, mas somente se o usuário for o dono."""
    conn = get_db()
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()

    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404

    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para deletar este setlist."}), 403

    conn.execute('DELETE FROM setlists WHERE id = ?', (setlist_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Setlist deletado com sucesso."})

@app.route('/api/setlists/<int:setlist_id>/songs', methods=['POST'])
@login_required
def add_song_to_setlist(setlist_id):
    """Adiciona uma música a um setlist específico."""
    conn = get_db()

    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    data = request.get_json()
    song_id = data.get('song_id')
    if not song_id:
        conn.close()
        return jsonify({"error": "ID da música é obrigatório."}), 400

    # Convert song_id to int and handle potential conversion errors
    try:
        song_id_int = int(song_id)
    except (ValueError, TypeError):
        conn.close()
        return jsonify({"error": f"ID de música inválido: {song_id}"}), 400

    existing = conn.execute(
        'SELECT id FROM setlist_songs WHERE setlist_id = ? AND song_id = ?',
        (setlist_id, song_id_int)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Esta música já está no setlist."}), 409

    max_pos_result = conn.execute('SELECT MAX(position) FROM setlist_songs WHERE setlist_id = ?', (setlist_id,)).fetchone()
    next_position = (max_pos_result[0] if max_pos_result[0] is not None else -1) + 1

    conn.execute(
        'INSERT INTO setlist_songs (setlist_id, song_id, position) VALUES (?, ?, ?)',
        (setlist_id, song_id_int, next_position)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Música adicionada ao setlist com sucesso!"}), 201

@app.route('/api/setlists/<int:setlist_id>/songs/<int:song_id>', methods=['DELETE'])
@login_required
def remove_song_from_setlist(setlist_id, song_id):
    """Remove uma música de um setlist específico."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    conn.execute(
        'DELETE FROM setlist_songs WHERE setlist_id = ? AND song_id = ?',
        (setlist_id, song_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Música removida do setlist com sucesso."})

@app.route('/api/setlists/<int:setlist_id>/songs/order', methods=['PUT'])
@login_required
def update_setlist_order(setlist_id):
    """Atualiza a ordem das músicas em um setlist."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    
    # Verificar se é o dono ou tem permissão de edição
    is_owner = setlist['user_id'] == current_user.id
    has_edit_permission = False
    
    if not is_owner:
        permission = conn.execute(
            'SELECT permission_type FROM setlist_permissions WHERE setlist_id = ? AND user_id = ?',
            (setlist_id, current_user.id)
        ).fetchone()
        has_edit_permission = permission and permission['permission_type'] == 'edit'
    
    if not is_owner and not has_edit_permission:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    data = request.get_json()
    song_ids = data.get('song_ids')

    if not isinstance(song_ids, list):
        conn.close()
        return jsonify({"error": "Payload inválido: 'song_ids' deve ser uma lista."}), 400

    try:
        # Usar uma transação para garantir a integridade dos dados
        for index, song_id in enumerate(song_ids):
            # Convert song_id to int and handle potential conversion errors
            try:
                song_id_int = int(song_id)
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": f"ID de música inválido: {song_id}"}), 400
            
            # Check if the song exists in the setlist before updating
            existing_song = conn.execute(
                "SELECT id FROM setlist_songs WHERE setlist_id = ? AND song_id = ?",
                (setlist_id, song_id_int)
            ).fetchone()
            
            if not existing_song:
                conn.close()
                return jsonify({"error": f"Música com ID {song_id_int} não encontrada no setlist"}), 404
            
            conn.execute(
                "UPDATE setlist_songs SET position = ? WHERE setlist_id = ? AND song_id = ?",
                (index, setlist_id, song_id_int)
            )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500
    
    conn.close()
    return jsonify({"message": "Ordem do setlist atualizada com sucesso."})

@app.route('/api/setlists/<int:setlist_id>/visibility', methods=['PUT'])
@login_required
def update_setlist_visibility(setlist_id):
    """Atualiza o status público/privado de um setlist."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    data = request.get_json()
    is_public = data.get('is_public')
    
    if not isinstance(is_public, bool):
        conn.close()
        return jsonify({"error": "Payload inválido: 'is_public' deve ser um booleano."}), 400

    try:
        conn.execute(
            'UPDATE setlists SET is_public = ? WHERE id = ?',
            (is_public, setlist_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Visibilidade do setlist atualizada com sucesso.", "is_public": is_public})
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/setlists/<int:setlist_id>/available-songs', methods=['GET'])
@login_required
def get_available_songs_for_setlist(setlist_id):
    """Busca músicas disponíveis para adicionar ao setlist (músicas do usuário que ainda não estão no setlist)."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para este setlist."}), 403

    try:
        # Busca músicas do usuário que não estão no setlist
        available_songs = conn.execute('''
            SELECT s.id, s.title, s.original_key, s.capo_position, s.duration, s.bpm
            FROM songs s
            WHERE s.user_id = ?
            AND s.id NOT IN (
                SELECT ss.song_id 
                FROM setlist_songs ss 
                WHERE ss.setlist_id = ?
            )
            ORDER BY s.title COLLATE NOCASE ASC
        ''', (current_user.id, setlist_id)).fetchall()
        
        conn.close()
        return jsonify([dict(song) for song in available_songs])
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

# --- SETLIST INVITES API ROUTES ---
@app.route('/api/setlists/<int:setlist_id>/invite', methods=['POST'])
@login_required
def invite_user_to_setlist(setlist_id):
    """Convida um usuário para acessar um setlist."""
    # Rate limiting para convites
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if is_invite_rate_limited(client_ip):
        return jsonify({"error": "Muitos convites enviados. Tente novamente em 1 hora."}), 429
    
    data = request.get_json()
    invited_user_id = data.get('user_id', '').strip()
    
    if not invited_user_id:
        return jsonify({"error": "ID do usuário é obrigatório."}), 400
    
    conn = get_db()
    
    # Verificar se o setlist existe e se o usuário atual é o dono
    setlist = conn.execute('SELECT user_id, name FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Apenas o dono do setlist pode enviar convites."}), 403
    
    # Verificar se o usuário convidado existe (buscar por username ou id)
    invited_user = conn.execute('SELECT id FROM users WHERE username = ? OR id = ?', (invited_user_id, invited_user_id)).fetchone()
    if not invited_user:
        conn.close()
        return jsonify({"error": "Usuário não encontrado."}), 404
    
    # Verificar se não está tentando convidar a si mesmo
    if invited_user['id'] == current_user.id:
        conn.close()
        return jsonify({"error": "Você não pode convidar a si mesmo."}), 400
    
    try:
        # Verificar se já existe um convite
        existing_invite = conn.execute(
            'SELECT status FROM setlist_invites WHERE setlist_id = ? AND invited_user_id = ?',
            (setlist_id, invited_user['id'])
        ).fetchone()
        
        if existing_invite:
            if existing_invite['status'] == 'accepted':
                conn.close()
                return jsonify({"error": "Usuário já tem acesso a este setlist."}), 400
            elif existing_invite['status'] == 'pending':
                conn.close()
                return jsonify({"error": "Convite já foi enviado para este usuário."}), 400
        
        # Criar o convite
        conn.execute(
            'INSERT INTO setlist_invites (setlist_id, inviter_id, invited_user_id) VALUES (?, ?, ?)',
            (setlist_id, current_user.id, invited_user['id'])
        )
        
        conn.commit()
        conn.close()
        
        # Registrar tentativa de convite após sucesso
        add_invite_attempt(client_ip)
        
        # Log de segurança
        security_logger.info(f"INVITE_SENT: User {current_user.id} invited user {invited_user['id']} to setlist {setlist_id} from IP {client_ip}")
        
        return jsonify({"message": f"Convite enviado com sucesso para o usuário {invited_user_id}."})
        
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/invites/pending', methods=['GET'])
@login_required
def get_pending_invites():
    """Lista convites pendentes para o usuário atual."""
    conn = get_db()
    
    try:
        pending_invites = conn.execute('''
            SELECT si.id, si.setlist_id, si.created_at, s.name as setlist_name, 
                   u.username as inviter_username
            FROM setlist_invites si
            JOIN setlists s ON si.setlist_id = s.id
            JOIN users u ON si.inviter_id = u.id
            WHERE si.invited_user_id = ? AND si.status = 'pending'
            ORDER BY si.created_at DESC
        ''', (current_user.id,)).fetchall()
        
        conn.close()
        return jsonify([dict(invite) for invite in pending_invites])
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/invites/<int:invite_id>/accept', methods=['POST'])
@login_required
def accept_invite(invite_id):
    """Aceita um convite para acessar um setlist."""
    conn = get_db()
    
    try:
        # Verificar se o convite existe e pertence ao usuário atual
        invite = conn.execute(
            'SELECT setlist_id, status FROM setlist_invites WHERE id = ? AND invited_user_id = ?',
            (invite_id, current_user.id)
        ).fetchone()
        
        if not invite:
            conn.close()
            return jsonify({"error": "Convite não encontrado."}), 404
        
        if invite['status'] != 'pending':
            conn.close()
            return jsonify({"error": "Convite já foi processado."}), 400
        
        # Aceitar o convite
        conn.execute(
            'UPDATE setlist_invites SET status = "accepted", accepted_at = CURRENT_TIMESTAMP WHERE id = ?',
            (invite_id,)
        )
        
        # Criar permissão de visualização
        conn.execute(
            'INSERT OR REPLACE INTO setlist_permissions (setlist_id, user_id, permission_type) VALUES (?, ?, "view_only")',
            (invite['setlist_id'], current_user.id)
        )
        
        conn.commit()
        conn.close()
        
        # Log de segurança
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        security_logger.info(f"INVITE_ACCEPTED: User {current_user.id} accepted invite {invite_id} from IP {client_ip}")
        
        return jsonify({"message": "Convite aceito com sucesso."})
        
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/invites/<int:invite_id>/reject', methods=['POST'])
@login_required
def reject_invite(invite_id):
    """Recusa um convite para acessar um setlist."""
    conn = get_db()
    
    try:
        # Verificar se o convite existe e pertence ao usuário atual
        invite = conn.execute(
            'SELECT setlist_id, status FROM setlist_invites WHERE id = ? AND invited_user_id = ?',
            (invite_id, current_user.id)
        ).fetchone()
        
        if not invite:
            conn.close()
            return jsonify({"error": "Convite não encontrado."}), 404
        
        if invite['status'] != 'pending':
            conn.close()
            return jsonify({"error": "Convite já foi processado."}), 400
        
        # Recusar o convite
        conn.execute(
            'UPDATE setlist_invites SET status = "rejected" WHERE id = ?',
            (invite_id,)
        )
        
        conn.commit()
        conn.close()
        
        # Log de segurança
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        security_logger.info(f"INVITE_REJECTED: User {current_user.id} rejected invite {invite_id} from IP {client_ip}")
        
        return jsonify({"message": "Convite recusado com sucesso."})
        
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/setlists/<int:setlist_id>/permissions', methods=['PUT'])
@login_required
def update_setlist_permission(setlist_id):
    """Atualiza a permissão de um usuário em um setlist (apenas para o dono)."""
    data = request.get_json()
    user_id = data.get('user_id')
    permission_type = data.get('permission_type')
    
    if not user_id or not permission_type:
        return jsonify({"error": "user_id e permission_type são obrigatórios."}), 400
    
    if permission_type not in ['view_only', 'edit']:
        return jsonify({"error": "permission_type deve ser 'view_only' ou 'edit'."}), 400
    
    conn = get_db()
    
    # Verificar se o setlist existe e se o usuário atual é o dono
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Apenas o dono do setlist pode alterar permissões."}), 403
    
    # Verificar se o usuário tem permissão no setlist
    existing_permission = conn.execute(
        'SELECT id FROM setlist_permissions WHERE setlist_id = ? AND user_id = ?',
        (setlist_id, user_id)
    ).fetchone()
    
    if not existing_permission:
        conn.close()
        return jsonify({"error": "Usuário não tem acesso a este setlist."}), 404
    
    try:
        # Atualizar a permissão
        conn.execute(
            'UPDATE setlist_permissions SET permission_type = ? WHERE setlist_id = ? AND user_id = ?',
            (permission_type, setlist_id, user_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({"message": f"Permissão atualizada para {permission_type} com sucesso."})
        
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/setlists/<int:setlist_id>/invites', methods=['GET'])
@login_required
def get_setlist_invites(setlist_id):
    """Lista convites de um setlist (apenas para o dono)."""
    conn = get_db()
    
    # Verificar se o setlist existe e se o usuário atual é o dono
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Apenas o dono do setlist pode ver os convites."}), 403
    
    try:
        invites = conn.execute('''
            SELECT si.id, si.invited_user_id, si.status, si.created_at, si.accepted_at,
                   u.username as invited_user_name,
                   sp.permission_type
            FROM setlist_invites si
            LEFT JOIN users u ON si.invited_user_id = u.id
            LEFT JOIN setlist_permissions sp ON si.setlist_id = sp.setlist_id AND si.invited_user_id = sp.user_id
            WHERE si.setlist_id = ?
            ORDER BY si.created_at DESC
        ''', (setlist_id,)).fetchall()
        
        conn.close()
        return jsonify([dict(invite) for invite in invites])
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500

@app.route('/api/user/profile', methods=['GET'])
@login_required
def get_user_profile():
    """Retorna informações do perfil do usuário atual."""
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "name": current_user.name,
        "email": current_user.email
    })

@app.route('/api/setlists/<int:setlist_id>/jam-session', methods=['GET'])
@login_required
def start_jam_session(setlist_id):
    """Inicia uma jam session retornando as músicas do setlist em ordem."""
    db = get_db()
    
    # Verificar se o usuário tem acesso ao setlist
    setlist = db.execute(
        'SELECT id, name, user_id, is_public FROM setlists WHERE id = ?',
        (setlist_id,)
    ).fetchone()

    if not setlist:
        db.close()
        return jsonify({"error": "Setlist não encontrado."}), 404

    is_owner = setlist['user_id'] == current_user.id
    has_permission = False
    
    if not is_owner:
        permission = db.execute(
            'SELECT permission_type FROM setlist_permissions WHERE setlist_id = ? AND user_id = ?',
            (setlist_id, current_user.id)
        ).fetchone()
        has_permission = permission is not None
    
    if not is_owner and not setlist['is_public'] and not has_permission:
        db.close()
        return jsonify({"error": "Acesso não autorizado."}), 403

    # Buscar músicas do setlist em ordem
    songs = db.execute(
        '''
        SELECT s.id, s.title, s.original_key, s.capo_position, s.duration, s.bpm, ss.position
        FROM songs s
        JOIN setlist_songs ss ON s.id = ss.song_id
        WHERE ss.setlist_id = ?
        ORDER BY ss.position ASC
        ''',
        (setlist_id,)
    ).fetchall()
    
    db.close()

    if not songs:
        return jsonify({"error": "Setlist vazio."}), 400

    return jsonify({
        "setlist_id": setlist['id'],
        "setlist_name": setlist['name'],
        "total_songs": len(songs),
        "songs": [dict(song) for song in songs]
    })

# Rotas para servir o frontend
@app.route('/')
def serve_frontend():
    """Serve o arquivo index.html do frontend"""
    return send_from_directory('../app', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve arquivos estáticos do frontend"""
    return send_from_directory('../app', path)


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)