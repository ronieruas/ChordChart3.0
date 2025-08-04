# Deploy em Produção - ChordChart Pro

Este guia explica como configurar o ChordChart Pro para produção usando Docker em um LXC do Proxmox com Cloudflare Tunnel.

## 📋 Pré-requisitos

- Proxmox LXC com Docker instalado
- Conta no Cloudflare
- Cloudflare Tunnel configurado

## 🚀 Configuração Rápida

### 1. Preparar o Ambiente

```bash
# Clonar o repositório
git clone <seu-repositorio>
cd ChordChart

# Copiar arquivo de configuração
cp env.production .env
```

### 2. Configurar o Arquivo .env

Edite o arquivo `.env` com as seguintes configurações:

```bash
# Gerar uma SECRET_KEY segura
SECRET_KEY=sua-chave-secreta-muito-segura-aqui

# Ambiente de produção
FLASK_ENV=production

# URLs do Cloudflare Tunnel (substitua pelo seu domínio)
ALLOWED_ORIGINS=https://seu-dominio.trycloudflare.com

# Configurações de segurança
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax
```

### 3. Executar o Deploy

```bash
# Tornar o script executável
chmod +x deploy-production.sh

# Executar deploy
./deploy-production.sh
```

## 🔧 Configuração Manual

Se preferir configurar manualmente:

```bash
# Build das imagens
docker-compose -f docker-compose.prod.yml build

# Iniciar serviços
docker-compose -f docker-compose.prod.yml up -d
```

## 🌐 Configuração do Cloudflare Tunnel

### 1. Instalar Cloudflare Tunnel

```bash
# Baixar cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb
```

### 2. Autenticar com Cloudflare

```bash
cloudflared tunnel login
```

### 3. Criar Tunnel

```bash
# Criar tunnel
cloudflared tunnel create chordchart-pro

# Listar tunnels
cloudflared tunnel list
```

### 4. Configurar Tunnel

Crie o arquivo `~/.cloudflared/config.yml`:

```yaml
tunnel: <SEU_TUNNEL_ID>
credentials-file: /home/user/.cloudflared/<SEU_TUNNEL_ID>.json

ingress:
  - hostname: seu-dominio.trycloudflare.com
    service: http://localhost:8080
  - service: http_status:404
```

### 5. Iniciar Tunnel

```bash
# Testar configuração
cloudflared tunnel --config ~/.cloudflared/config.yml ingress validate

# Iniciar tunnel
cloudflared tunnel --config ~/.cloudflared/config.yml run
```

## 🔒 Configurações de Segurança

### Firewall (UFW)

```bash
# Instalar UFW
sudo apt install ufw

# Configurar regras
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp

# Ativar firewall
sudo ufw enable
```

### Fail2ban

```bash
# Instalar fail2ban
sudo apt install fail2ban

# Configurar para nginx
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

## 📊 Monitoramento

### Logs

```bash
# Ver logs em tempo real
docker-compose -f docker-compose.prod.yml logs -f

# Ver logs específicos
docker-compose -f docker-compose.prod.yml logs backend
docker-compose -f docker-compose.prod.yml logs frontend
```

### Health Checks

```bash
# Verificar status dos containers
docker-compose -f docker-compose.prod.yml ps

# Testar health check
curl http://localhost:8080/health
```

## 🔄 Atualizações

### Backup

```bash
# Backup do banco de dados
docker exec chordchart_pro_backend_prod sqlite3 /app/songs.db ".backup /app/backup_$(date +%Y%m%d_%H%M%S).db"
```

### Atualização

```bash
# Parar serviços
docker-compose -f docker-compose.prod.yml down

# Pull das últimas mudanças
git pull

# Rebuild e restart
docker-compose -f docker-compose.prod.yml build --no-cache
docker-compose -f docker-compose.prod.yml up -d
```

## 🚨 Troubleshooting

### Problemas Comuns

1. **Erro de CORS**
   - Verificar `ALLOWED_ORIGINS` no `.env`
   - Confirmar domínio do Cloudflare Tunnel

2. **Erro de Conexão**
   - Verificar se a porta 8080 está liberada
   - Confirmar configuração do Cloudflare Tunnel

3. **Erro de Sessão**
   - Verificar `SECRET_KEY` no `.env`
   - Confirmar `SESSION_COOKIE_SECURE=true`

### Logs de Debug

```bash
# Logs detalhados do backend
docker-compose -f docker-compose.prod.yml logs backend --tail=100

# Logs do nginx
docker-compose -f docker-compose.prod.yml logs frontend --tail=100
```

## 📞 Suporte

Para problemas específicos:

1. Verificar logs dos containers
2. Confirmar configurações do `.env`
3. Testar conectividade do Cloudflare Tunnel
4. Verificar firewall e portas

## 🔐 Segurança Adicional

- Use senhas fortes para todos os usuários
- Configure backup automático do banco de dados
- Monitore logs regularmente
- Mantenha o sistema atualizado
- Use HTTPS sempre (Cloudflare Tunnel já fornece) 