# Configuração Ideal do LXC para ChordChart Pro

## 📋 **Especificações Recomendadas**

### 🖥️ **Recursos Mínimos**
```
CPU: 2 vCPUs
RAM: 2 GB
Storage: 20 GB
Network: 1 Gbps
```

### 🚀 **Recursos Recomendados**
```
CPU: 4 vCPUs
RAM: 4 GB
Storage: 50 GB
Network: 1 Gbps
```

### ⚡ **Recursos para Alta Performance**
```
CPU: 8 vCPUs
RAM: 8 GB
Storage: 100 GB SSD
Network: 1 Gbps
```

## 🔧 **Configuração do LXC no Proxmox**

### 1. **Criar Container LXC**

```bash
# Via interface web do Proxmox
1. Datacenter > Node > LXC > Create CT
2. Template: Ubuntu 22.04 LTS
3. ID: 100 (ou próximo disponível)
4. Hostname: chordchart-pro
```

### 2. **Configuração de Recursos**

```bash
# CPU
Cores: 4
CPU Units: 2048

# Memory
Memory: 4096 MB
Swap: 1024 MB

# Storage
Root Disk: 50 GB
Storage: local-lvm (ou seu storage preferido)

# Network
Bridge: vmbr0
IPv4: DHCP (ou IP fixo)
```

### 3. **Configuração Avançada**

```bash
# Features
Nesting: ✓ (para Docker)
Keyctl: ✓
FUSE: ✓

# Options
Start at boot: ✓
Startup order: 1
Startup delay: 0
Shutdown timeout: 60
```

## 🐧 **Configuração do Sistema Operacional**

### 1. **Atualizar Sistema**

```bash
# Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# Instalar dependências básicas
sudo apt install -y curl wget git nano htop
```

### 2. **Configurar Timezone**

```bash
# Configurar timezone para Brasil
sudo timedatectl set-timezone America/Sao_Paulo

# Verificar configuração
timedatectl status
```

### 3. **Configurar Locale**

```bash
# Configurar locale para português
sudo locale-gen pt_BR.UTF-8
sudo update-locale LANG=pt_BR.UTF-8
```

## 🐳 **Instalação do Docker**

### 1. **Instalar Docker**

```bash
# Remover versões antigas
sudo apt remove docker docker-engine docker.io containerd runc

# Instalar dependências
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Adicionar repositório oficial
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Instalar Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

### 2. **Configurar Docker**

```bash
# Adicionar usuário ao grupo docker
sudo usermod -aG docker $USER

# Habilitar Docker no boot
sudo systemctl enable docker
sudo systemctl start docker

# Verificar instalação
docker --version
docker-compose --version
```

### 3. **Configurar Docker Compose**

```bash
# Instalar Docker Compose (se necessário)
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## 🔒 **Configurações de Segurança**

### 1. **Firewall (UFW)**

```bash
# Instalar UFW
sudo apt install -y ufw

# Configurar regras
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp

# Ativar firewall
sudo ufw enable
```

### 2. **Fail2ban**

```bash
# Instalar fail2ban
sudo apt install -y fail2ban

# Configurar
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Editar configuração
sudo nano /etc/fail2ban/jail.local

# Adicionar ao final do arquivo:
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600
findtime = 600

# Reiniciar fail2ban
sudo systemctl restart fail2ban
```

### 3. **Configurar SSH**

```bash
# Editar configuração SSH
sudo nano /etc/ssh/sshd_config

# Adicionar/modificar:
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Reiniciar SSH
sudo systemctl restart ssh
```

## 🌐 **Configuração de Rede**

### 1. **Configurar IP Fixo (Opcional)**

```bash
# Editar configuração de rede
sudo nano /etc/netplan/01-netcfg.yaml

# Exemplo de configuração:
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 192.168.1.100/24
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]

# Aplicar configuração
sudo netplan apply
```

### 2. **Configurar DNS**

```bash
# Editar resolv.conf
sudo nano /etc/resolv.conf

# Adicionar:
nameserver 8.8.8.8
nameserver 8.8.4.4
```

## 📊 **Monitoramento**

### 1. **Instalar Ferramentas de Monitoramento**

```bash
# Instalar htop, iotop, nethogs
sudo apt install -y htop iotop nethogs

# Instalar logwatch
sudo apt install -y logwatch

# Configurar logwatch
sudo nano /etc/cron.daily/00logwatch
```

### 2. **Configurar Logs**

```bash
# Criar diretório para logs
sudo mkdir -p /var/log/chordchart

# Configurar rotação de logs
sudo nano /etc/logrotate.d/chordchart

# Adicionar:
/var/log/chordchart/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
```

## 🚀 **Deploy da Aplicação**

### 1. **Clonar Repositório**

```bash
# Criar diretório
mkdir -p /opt/chordchart
cd /opt/chordchart

# Clonar repositório
git clone <seu-repositorio> .

# Dar permissões
sudo chown -R $USER:$USER /opt/chordchart
```

### 2. **Configurar Ambiente**

```bash
# Copiar arquivo de configuração
cp env.production .env

# Editar configurações
nano .env

# Configurar:
SECRET_KEY=sua-chave-secreta-muito-segura
FLASK_ENV=production
ALLOWED_ORIGINS=https://seu-dominio.trycloudflare.com
```

### 3. **Executar Deploy**

```bash
# Tornar script executável
chmod +x deploy-production.sh

# Executar deploy
./deploy-production.sh
```

## 🔧 **Configuração do Cloudflare Tunnel**

### 1. **Instalar Cloudflared**

```bash
# Baixar cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb

# Instalar
sudo dpkg -i cloudflared-linux-amd64.deb
```

### 2. **Configurar Tunnel**

```bash
# Autenticar
cloudflared tunnel login

# Criar tunnel
cloudflared tunnel create chordchart-pro

# Configurar
nano ~/.cloudflared/config.yml

# Adicionar:
tunnel: <SEU_TUNNEL_ID>
credentials-file: /home/user/.cloudflared/<SEU_TUNNEL_ID>.json

ingress:
  - hostname: seu-dominio.trycloudflare.com
    service: http://localhost:8080
  - service: http_status:404
```

### 3. **Configurar como Serviço**

```bash
# Instalar como serviço
sudo cloudflared service install

# Habilitar no boot
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

## 📈 **Otimizações de Performance**

### 1. **Configurar Swap**

```bash
# Verificar swap atual
free -h

# Se necessário, aumentar swap
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Adicionar ao fstab
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 2. **Otimizar Docker**

```bash
# Criar daemon.json
sudo nano /etc/docker/daemon.json

# Adicionar:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}

# Reiniciar Docker
sudo systemctl restart docker
```

### 3. **Configurar Limites de Sistema**

```bash
# Editar limits.conf
sudo nano /etc/security/limits.conf

# Adicionar:
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
```

## 🔍 **Verificação Final**

### 1. **Testar Funcionalidades**

```bash
# Verificar Docker
docker ps
docker-compose -f docker-compose.prod.yml ps

# Verificar portas
netstat -tlnp | grep :8080

# Verificar logs
docker-compose -f docker-compose.prod.yml logs
```

### 2. **Testar Acesso**

```bash
# Testar localmente
curl http://localhost:8080/health

# Testar via Cloudflare Tunnel
curl https://seu-dominio.trycloudflare.com/health
```

## 📞 **Comandos Úteis**

### **Monitoramento**
```bash
# Ver uso de recursos
htop
iotop
nethogs

# Ver logs
docker-compose -f docker-compose.prod.yml logs -f

# Ver status dos containers
docker-compose -f docker-compose.prod.yml ps
```

### **Manutenção**
```bash
# Backup do banco
docker exec chordchart_pro_backend_prod sqlite3 /app/songs.db ".backup /app/backup_$(date +%Y%m%d_%H%M%S).db"

# Atualizar aplicação
git pull
docker-compose -f docker-compose.prod.yml build --no-cache
docker-compose -f docker-compose.prod.yml up -d

# Reiniciar serviços
docker-compose -f docker-compose.prod.yml restart
```

### **Troubleshooting**
```bash
# Ver logs detalhados
docker-compose -f docker-compose.prod.yml logs backend --tail=100
docker-compose -f docker-compose.prod.yml logs frontend --tail=100

# Verificar conectividade
ping 8.8.8.8
nslookup google.com

# Verificar firewall
sudo ufw status
```

## 🎯 **Configuração Recomendada Final**

Para um ambiente de produção estável, recomendo:

```
LXC Container:
- CPU: 4 vCPUs
- RAM: 4 GB
- Storage: 50 GB SSD
- Network: 1 Gbps
- OS: Ubuntu 22.04 LTS
- Features: Nesting, Keyctl, FUSE habilitados

Segurança:
- UFW ativo
- Fail2ban configurado
- SSH seguro
- Firewall configurado

Monitoramento:
- Logs estruturados
- Health checks
- Backup automático
- Alertas configurados
```

Esta configuração oferece um equilíbrio ideal entre performance, segurança e facilidade de manutenção! 🚀 