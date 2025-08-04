import os
import sqlite3
import unicodedata
import re
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import time
from collections import defaultdict

app = Flask(__name__)

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
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5 minutos

def is_rate_limited(ip):
    """Verifica se o IP está limitado por tentativas de login"""
    now = time.time()
    # Remove tentativas antigas
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOGIN_TIMEOUT]
    return len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def add_login_attempt(ip):
    """Adiciona uma tentativa de login para o IP"""
    login_attempts[ip].append(time.time())

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
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

app.after_request(add_security_headers)

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = 'songs.db'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'])
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
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
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
        
        # Depois, verificar se as colunas existem e adicionar se necessário
        try:
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
    if not is_owner and not setlist['is_public']:
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

    response_data = {
        "id": setlist['id'],
        "name": setlist['name'],
        "is_public": setlist['is_public'],
        "is_owner": is_owner,
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
    if setlist['user_id'] != current_user.id:
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


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)