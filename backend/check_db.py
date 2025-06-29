import sqlite3

try:
    conn = sqlite3.connect('songs.db')
    cursor = conn.cursor()
    
    # Verificar se a tabela users existe
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if cursor.fetchone():
        print("✅ Tabela 'users' existe")
        
        # Verificar usuários
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()
        print(f"📋 Usuários no banco: {users}")
        
        if users:
            # Verificar estrutura da tabela
            cursor.execute("PRAGMA table_info(users)")
            columns = cursor.fetchall()
            print(f"📊 Estrutura da tabela users: {columns}")
        else:
            print("❌ Nenhum usuário encontrado no banco")
    else:
        print("❌ Tabela 'users' não existe")
        
    conn.close()
    
except Exception as e:
    print(f"❌ Erro: {e}") 