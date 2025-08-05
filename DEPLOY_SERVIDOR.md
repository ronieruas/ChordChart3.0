# 🚀 Guia Completo de Deploy no Servidor

## 📋 **Pré-requisitos no Servidor**

### ✅ **Verificar se tem:**
- Docker instalado
- Docker Compose instalado
- Git instalado
- Acesso SSH ao servidor

## 🔧 **Passo a Passo no Servidor**

### 1. **📥 Clonar o Repositório**

```bash
# Navegar para diretório de aplicações
cd /opt

# Clonar o repositório
git clone <URL_DO_SEU_REPOSITORIO> chordchart

# Entrar no diretório
cd chordchart
```

### 2. **⚙️ Configurar Ambiente**

```bash
# Copiar arquivo de configuração
cp env.production .env

# Editar configurações
nano .env
```

**Configurar no arquivo `.env`:**
```bash
# Chave secreta (GERE UMA NOVA!)
SECRET_KEY=sua-chave-super-secreta-muito-longa-123456789

# Ambiente
FLASK_ENV=production

# CORS - Configure com seu domínio do Cloudflare
ALLOWED_ORIGINS=https://seu-dominio.trycloudflare.com

# Outras configurações já estão corretas
```

### 3. **🐳 Executar Deploy**

```bash
# Tornar script executável
chmod +x deploy-production.sh

# Executar deploy
./deploy-production.sh
```

### 4. **👤 Criar Usuário Admin**

```bash
# Criar usuário admin
docker exec chordchart_pro_backend_prod python3 create_user.py admin --generate-password
```

**Salve a senha gerada!** 🔐

### 5. **🌐 Configurar Cloudflare Tunnel**

```bash
# Instalar cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Autenticar
cloudflared tunnel login

# Criar tunnel
cloudflared tunnel create chordchart-pro

# Configurar
nano ~/.cloudflared/config.yml
```

**Conteúdo do `config.yml`:**
```yaml
tunnel: <SEU_TUNNEL_ID>
credentials-file: /home/user/.cloudflared/<SEU_TUNNEL_ID>.json

ingress:
  - hostname: seu-dominio.trycloudflare.com
    service: http://localhost:8080
  - service: http_status:404
```

```bash
# Instalar como serviço
sudo cloudflared service install

# Habilitar no boot
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

## 🔍 **Verificação**

### **Testar Aplicação:**
```bash
# Verificar containers
docker ps

# Verificar logs
docker-compose -f docker-compose.prod.yml logs

# Testar localmente
curl http://localhost:8080/health
```

### **Testar Cloudflare Tunnel:**
```bash
# Verificar status
sudo systemctl status cloudflared

# Testar acesso
curl https://seu-dominio.trycloudflare.com/health
```

## 📞 **Comandos Úteis**

### **Monitoramento:**
```bash
# Ver logs em tempo real
docker-compose -f docker-compose.prod.yml logs -f

# Ver uso de recursos
htop
docker stats
```

### **Manutenção:**
```bash
# Atualizar aplicação
git pull
./deploy-production.sh

# Reiniciar serviços
docker-compose -f docker-compose.prod.yml restart

# Backup do banco
docker exec chordchart_pro_backend_prod sqlite3 /app/songs.db ".backup /app/backup_$(date +%Y%m%d_%H%M%S).db"
```

### **Troubleshooting:**
```bash
# Ver logs detalhados
docker-compose -f docker-compose.prod.yml logs backend --tail=100
docker-compose -f docker-compose.prod.yml logs frontend --tail=100

# Verificar conectividade
ping 8.8.8.8
nslookup google.com
```

## 🎯 **Checklist Final**

- [ ] Repositório clonado
- [ ] Arquivo `.env` configurado
- [ ] Containers rodando
- [ ] Usuário admin criado
- [ ] Cloudflare Tunnel configurado
- [ ] Acesso via URL funcionando
- [ ] Login funcionando

## 🔧 **Arquivos Importantes**

- `docker-compose.prod.yml` - Configuração de produção
- `env.production` - Template de configuração
- `nginx-cloudflare.conf` - Configuração Nginx para Cloudflare
- `deploy-production.sh` - Script de deploy
- `LXC_CONFIGURATION.md` - Configuração do LXC
- `SOLUCAO_CREATE_USER.md` - Solução para criar usuários

## 🚨 **Segurança**

### **Configurar Firewall:**
```bash
# Instalar UFW
sudo apt install ufw

# Configurar regras
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp

# Ativar
sudo ufw enable
```

### **Configurar Fail2ban:**
```bash
# Instalar
sudo apt install fail2ban

# Configurar
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local

# Reiniciar
sudo systemctl restart fail2ban
```

## ✅ **Sucesso!**

Após seguir todos os passos, sua aplicação estará:
- ✅ Rodando em produção
- ✅ Acessível via Cloudflare Tunnel
- ✅ Segura com firewall e fail2ban
- ✅ Monitorada com logs estruturados
- ✅ Pronta para uso!

**URL de acesso:** `https://seu-dominio.trycloudflare.com`

---

**💡 Dica:** Mantenha as credenciais do usuário admin em local seguro e faça backup regular do banco de dados! 