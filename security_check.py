#!/usr/bin/env python3
"""
Script de Verificação de Segurança - ChordChart Pro
Verifica se as configurações de segurança estão corretas
"""

import os
import re
import sqlite3
from werkzeug.security import generate_password_hash

def check_env_file():
    """Verifica se o arquivo .env existe e tem configurações seguras"""
    print("🔍 Verificando arquivo .env...")
    
    if not os.path.exists('.env'):
        print("❌ Arquivo .env não encontrado!")
        print("   Execute: cp env.example .env")
        return False
    
    with open('.env', 'r') as f:
        content = f.read()
    
    issues = []
    
    # Verifica SECRET_KEY
    if 'your-super-secret-key-change-this-in-production-123456789' in content:
        issues.append("SECRET_KEY ainda está com valor padrão")
    
    # Verifica FLASK_ENV
    if 'FLASK_ENV=production' not in content:
        issues.append("FLASK_ENV não está configurado para produção")
    
    if issues:
        print("⚠️  Problemas encontrados:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    print("✅ Arquivo .env configurado corretamente")
    return True

def check_database():
    """Verifica se o banco de dados existe e tem estrutura correta"""
    print("\n🔍 Verificando banco de dados...")
    
    if not os.path.exists('backend/songs.db'):
        print("❌ Banco de dados não encontrado!")
        print("   Execute a aplicação pelo menos uma vez para criar o banco")
        return False
    
    try:
        conn = sqlite3.connect('backend/songs.db')
        cursor = conn.cursor()
        
        # Verifica se a tabela users existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("❌ Tabela 'users' não encontrada!")
            return False
        
        # Verifica estrutura da tabela users
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        required_columns = ['id', 'username', 'password_hash']
        for col in required_columns:
            if col not in columns:
                print(f"❌ Coluna '{col}' não encontrada na tabela users!")
                return False
        
        # Verifica se há usuários
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        if user_count == 0:
            print("⚠️  Nenhum usuário encontrado no banco")
            print("   Execute: cd backend && python create_user.py admin --generate-password")
        else:
            print(f"✅ {user_count} usuário(s) encontrado(s)")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erro ao verificar banco de dados: {e}")
        return False

def check_ssl_config():
    """Verifica se há configuração SSL"""
    print("\n🔍 Verificando configuração SSL...")
    
    if os.path.exists('nginx-ssl.conf'):
        print("✅ Arquivo de configuração SSL encontrado")
        print("   Configure seus certificados SSL antes de usar em produção")
    else:
        print("⚠️  Arquivo nginx-ssl.conf não encontrado")
        print("   Use o arquivo nginx-ssl.conf para configuração HTTPS")

def check_file_permissions():
    """Verifica permissões de arquivos sensíveis"""
    print("\n🔍 Verificando permissões de arquivos...")
    
    sensitive_files = [
        '.env',
        'backend/songs.db',
        'backend/app.py'
    ]
    
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            perms = oct(os.stat(file_path).st_mode)[-3:]
            if perms != '600' and perms != '644':
                print(f"⚠️  {file_path}: permissões {perms} (recomendado: 600 para .env, 644 para outros)")

def main():
    """Executa todas as verificações de segurança"""
    print("🛡️  VERIFICAÇÃO DE SEGURANÇA - ChordChart Pro")
    print("=" * 50)
    
    checks = [
        check_env_file,
        check_database,
        check_ssl_config,
        check_file_permissions
    ]
    
    passed = 0
    total = len(checks)
    
    for check in checks:
        try:
            if check():
                passed += 1
        except Exception as e:
            print(f"❌ Erro durante verificação: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 RESULTADO: {passed}/{total} verificações passaram")
    
    if passed == total:
        print("🎉 Todas as verificações de segurança passaram!")
    else:
        print("⚠️  Algumas verificações falharam. Revise as configurações acima.")
    
    print("\n💡 DICAS DE SEGURANÇA:")
    print("   - Sempre use HTTPS em produção")
    print("   - Mantenha o sistema atualizado")
    print("   - Monitore logs de acesso")
    print("   - Faça backups regulares do banco de dados")
    print("   - Use senhas fortes e únicas")

if __name__ == '__main__':
    main() 