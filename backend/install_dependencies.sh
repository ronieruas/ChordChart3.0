#!/bin/bash

# Script para instalar dependências do ChordChart Pro localmente
# Útil para executar scripts fora do Docker

echo "🔧 Instalando dependências do ChordChart Pro..."

# Verificar se pip está instalado
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 não encontrado. Instalando..."
    sudo apt update
    sudo apt install -y python3-pip
fi

# Instalar dependências do requirements.txt
echo "📦 Instalando dependências Python..."
pip3 install -r requirements.txt

echo "✅ Dependências instaladas com sucesso!"
echo ""
echo "🔧 Agora você pode executar:"
echo "   python3 create_user.py admin --generate-password"
echo ""
echo "📋 Ou usar a versão standalone:"
echo "   python3 create_user_standalone.py admin --generate-password" 