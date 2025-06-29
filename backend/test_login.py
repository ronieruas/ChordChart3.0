import sqlite3
from werkzeug.security import check_password_hash

def test_login(username, password):
    """Testa se as credenciais estão corretas"""
    try:
        conn = sqlite3.connect('songs.db')
        cursor = conn.cursor()
        
        # Busca o usuário
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        
        if user_data:
            print(f"✅ Usuário '{username}' encontrado")
            print(f"📋 ID: {user_data[0]}")
            print(f"📋 Username: {user_data[1]}")
            print(f"📋 Password Hash: {user_data[2][:20]}...")
            
            # Testa a senha
            if check_password_hash(user_data[2], password):
                print("✅ Senha está correta!")
                return True
            else:
                print("❌ Senha está incorreta!")
                return False
        else:
            print(f"❌ Usuário '{username}' não encontrado!")
            return False
            
    except Exception as e:
        print(f"❌ Erro: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # Testa com a nova senha
    username = "admin"
    password = "Admin123!"
    
    print("🔍 Testando autenticação...")
    print(f"👤 Usuário: {username}")
    print(f"🔐 Senha: {password}")
    print("-" * 50)
    
    success = test_login(username, password)
    
    if success:
        print("\n✅ Autenticação bem-sucedida!")
        print("💡 Se ainda não consegue logar na web, verifique:")
        print("   1. Se o FLASK_ENV está configurado corretamente")
        print("   2. Se o SECRET_KEY está sendo usado")
        print("   3. Se as configurações de CORS estão corretas")
    else:
        print("\n❌ Falha na autenticação!")
        print("💡 Verifique se a senha está correta") 