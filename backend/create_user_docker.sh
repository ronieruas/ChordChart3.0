#!/bin/bash

# Script para criar usuário usando Docker
# Executa o create_user.py dentro do container

echo "🐳 Criando usuário via Docker..."

# Verificar se o container está rodando
if ! docker ps | grep -q "chordchart_pro_backend_prod"; then
    echo "❌ Container do backend não está rodando!"
    echo "🚀 Iniciando containers..."
    docker-compose -f ../docker-compose.prod.yml up -d
    sleep 5
fi

# Executar o comando dentro do container
echo "👤 Criando usuário admin..."
docker exec chordchart_pro_backend_prod python3 create_user.py admin --generate-password

echo ""
echo "✅ Usuário criado com sucesso!"
echo "🔗 Acesse a aplicação e faça login com as credenciais geradas acima." 