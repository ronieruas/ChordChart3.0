# 🔧 Solução para o Erro do create_user.py

## ❌ **Problema Identificado**
```
ModuleNotFoundError: No module named 'werkzeug'
```

## 🎯 **Soluções Disponíveis**

### 🐳 **Opção 1: Usar Docker (Recomendado)**

Execute o comando dentro do container Docker onde todas as dependências já estão instaladas:

```bash
# Navegar para o diretório do projeto
cd /opt/chordchart

# Executar via Docker
docker exec chordchart_pro_backend python3 create_user.py admin --generate-password
```

**Ou usar o script automatizado:**
```bash
./backend/create_user_docker.sh
```

### 📦 **Opção 2: Instalar Dependências Localmente**

#### **No Linux/Mac:**
```bash
# Instalar dependências
./backend/install_dependencies.sh

# Executar o script original
python3 create_user.py admin --generate-password
```

#### **No Windows (PowerShell):**
```powershell
# Executar script PowerShell
.\backend\install_dependencies.ps1

# Executar o script original
python create_user.py admin --generate-password
```

### 🔧 **Opção 3: Usar Versão Standalone**

Use a versão que não depende do `werkzeug`:

```bash
# Linux/Mac
python3 backend/create_user_standalone.py admin --generate-password

# Windows
python backend/create_user_standalone.py admin --generate-password
```

## 🚀 **Passo a Passo Recomendado**

### 1. **Verificar se o Docker está rodando**
```bash
docker ps
```

### 2. **Se não estiver rodando, iniciar os containers**
```bash
cd /opt/chordchart
docker-compose -f docker-compose.prod.yml up -d
```

### 3. **Criar o usuário admin**
```bash
docker exec chordchart_pro_backend_prod python3 create_user.py admin --generate-password
```

### 4. **Salvar as credenciais**
- Anote a senha gerada automaticamente
- Use essas credenciais para fazer login na aplicação

## 📋 **Exemplo de Saída Esperada**

```
🔐 Senha gerada automaticamente: K8m#nP9$vL2x
⚠️  IMPORTANTE: Salve esta senha em um local seguro!
✅ Usuário 'admin' criado com sucesso!
```

## 🔍 **Troubleshooting**

### **Erro: Container não encontrado**
```bash
# Verificar containers
docker ps -a

# Se não existir, criar
docker-compose -f docker-compose.prod.yml up -d
```

### **Erro: Permissão negada**
```bash
# Dar permissão de execução aos scripts
chmod +x backend/*.sh
```

### **Erro: Python não encontrado**
```bash
# Instalar Python
sudo apt update
sudo apt install python3 python3-pip
```

## 🎯 **Comandos Rápidos**

### **Criar usuário admin com senha automática:**
```bash
docker exec chordchart_pro_backend_prod python3 create_user.py admin --generate-password
```

### **Criar usuário com senha específica:**
```bash
docker exec chordchart_pro_backend_prod python3 create_user.py admin MinhaSenha123
```

### **Criar múltiplos usuários:**
```bash
docker exec chordchart_pro_backend_prod python3 create_user.py usuario1 --generate-password
docker exec chordchart_pro_backend_prod python3 create_user.py usuario2 --generate-password
```

## ✅ **Verificação Final**

Após criar o usuário, teste o login:

1. **Acesse a aplicação** via Cloudflare Tunnel
2. **Use as credenciais** geradas
3. **Verifique se o login funciona** corretamente

## 🔧 **Arquivos Criados**

- `backend/create_user_standalone.py` - Versão sem dependências externas
- `backend/install_dependencies.sh` - Script para instalar dependências (Linux/Mac)
- `backend/install_dependencies.ps1` - Script para instalar dependências (Windows)
- `backend/create_user_docker.sh` - Script para executar via Docker

---

**💡 Dica:** A solução mais simples e recomendada é usar o Docker, pois todas as dependências já estão configuradas no container. 