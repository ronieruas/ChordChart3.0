import sqlite3
from werkzeug.security import generate_password_hash

def reset_admin_user():
    """Deleta o usuário admin existente e cria um novo com senha conhecida"""
    try:
        conn = sqlite3.connect('songs.db')
        cursor = conn.cursor()
        
        # Deleta o usuário admin existente
        cursor.execute("DELETE FROM users WHERE username = ?", ('admin',))
        print("🗑️  Usuário admin anterior removido")
        
        # Cria novo usuário admin com senha conhecida
        password = "Admin123!"
        password_hash = generate_password_hash(password)
        
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       ('admin', password_hash))
        
        conn.commit()
        print(f"✅ Novo usuário admin criado!")
        print(f"👤 Usuário: admin")
        print(f"🔐 Senha: {password}")
        print("⚠️  IMPORTANTE: Use esta senha para fazer login!")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    print("🔄 Resetando usuário admin...")
    success = reset_admin_user()
    
    if success:
        print("\n✅ Reset concluído com sucesso!")
        print("💡 Agora você pode fazer login com:")
        print("   Usuário: admin")
        print("   Senha: Admin123!")
    else:
        print("\n❌ Falha no reset!") 