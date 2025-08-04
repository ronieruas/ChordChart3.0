#!/bin/bash

# Script de Deploy para Produção - ChordChart Pro
# Configurado para Cloudflare Tunnel

set -e

echo "🚀 Iniciando deploy para produção..."

# Verificar se o arquivo .env existe
if [ ! -f .env ]; then
    echo "❌ Arquivo .env não encontrado!"
    echo "📝 Copiando env.production para .env..."
    cp env.production .env
    echo "⚠️  IMPORTANTE: Configure o arquivo .env antes de continuar!"
    echo "   - Altere SECRET_KEY para uma chave segura"
    echo "   - Configure ALLOWED_ORIGINS com seu domínio do Cloudflare"
    exit 1
fi

# Verificar se as configurações críticas estão definidas
if grep -q "your-super-secret-key-change-this-in-production" .env; then
    echo "❌ SECRET_KEY ainda não foi configurada!"
    echo "⚠️  Configure uma SECRET_KEY segura no arquivo .env"
    exit 1
fi

if grep -q "seu-dominio.trycloudflare.com" .env; then
    echo "❌ ALLOWED_ORIGINS ainda não foi configurada!"
    echo "⚠️  Configure ALLOWED_ORIGINS com seu domínio do Cloudflare"
    exit 1
fi

echo "✅ Configurações verificadas!"

# Parar containers existentes
echo "🛑 Parando containers existentes..."
docker-compose -f docker-compose.prod.yml down

# Rebuild das imagens
echo "🔨 Rebuild das imagens..."
docker-compose -f docker-compose.prod.yml build --no-cache

# Iniciar containers
echo "🚀 Iniciando containers..."
docker-compose -f docker-compose.prod.yml up -d

# Aguardar inicialização
echo "⏳ Aguardando inicialização dos serviços..."
sleep 10

# Verificar status
echo "🔍 Verificando status dos containers..."
docker-compose -f docker-compose.prod.yml ps

# Verificar logs
echo "📋 Logs dos containers:"
docker-compose -f docker-compose.prod.yml logs --tail=20

echo ""
echo "✅ Deploy concluído!"
echo ""
echo "📋 Informações importantes:"
echo "   - Aplicação rodando na porta 8080"
echo "   - Configure o Cloudflare Tunnel para apontar para:"
echo "     http://localhost:8080"
echo "   - URL do Cloudflare Tunnel será algo como:"
echo "     https://seu-dominio.trycloudflare.com"
echo ""
echo "🔧 Comandos úteis:"
echo "   - Ver logs: docker-compose -f docker-compose.prod.yml logs -f"
echo "   - Parar: docker-compose -f docker-compose.prod.yml down"
echo "   - Reiniciar: docker-compose -f docker-compose.prod.yml restart" 