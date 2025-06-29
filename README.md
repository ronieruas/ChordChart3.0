# ChordChart Pro 3.0

Uma aplicação web avançada para criação e gerenciamento de cifras musicais, com sistema de login seguro e funcionalidades de setlist.

## 🚀 **Instalação Rápida**

### Pré-requisitos
- Docker e Docker Compose instalados
- Git

### 1. Clone o repositório
```bash
git clone https://github.com/SEU_USUARIO/chordchart-pro.git
cd chordchart-pro
```

### 2. Configure as variáveis de ambiente
```bash
cp env.example .env
```

### 3. Gere uma SECRET_KEY segura
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Edite o arquivo `.env` e substitua `your-super-secret-key-change-this-in-production-123456789` pela chave gerada.

### 4. Inicie a aplicação
```bash
docker-compose up -d
```

### 5. Crie o usuário administrador
```bash
cd backend
python3 create_user.py admin --generate-password
```
**IMPORTANTE:** Salve a senha gerada em um local seguro!

### 6. Acesse a aplicação
Abra seu navegador e acesse: `http://localhost:8080`

## 🔒 **Configuração de Segurança**

### Para Produção
1. **Configure HTTPS:**
   - Use o arquivo `nginx-ssl.conf` como base
   - Configure seus certificados SSL
   - Ative `FLASK_ENV=production` no `.env`

2. **Altere a SECRET_KEY:**
   - Nunca use a chave padrão em produção
   - Gere uma nova chave segura

3. **Configure CORS:**
   - Altere `ALLOWED_ORIGINS` no `.env` para seus domínios específicos

### Melhorias de Segurança Implementadas:
- ✅ **Rate Limiting**: Máximo 5 tentativas de login por IP em 5 minutos
- ✅ **Validação de Senha**: Mínimo 8 caracteres, maiúscula, minúscula e número
- ✅ **Headers de Segurança**: XSS, CSRF, Clickjacking protection
- ✅ **Sessões Seguras**: HttpOnly cookies, SameSite, timeout de 1 hora
- ✅ **Validação de Entrada**: Sanitização de dados de entrada
- ✅ **Criptografia**: Senhas hasheadas com Werkzeug
- ✅ **Proteção contra Força Bruta**: Bloqueio temporário após falhas

## 🛠️ **Estrutura do Projeto**

```
chordchart-pro/
├── docker-compose.yml       # Configuração Docker
├── nginx.conf              # Configuração Nginx
├── nginx-ssl.conf          # Configuração Nginx com SSL
├── env.example             # Exemplo de variáveis de ambiente
├── .gitignore              # Arquivos ignorados pelo Git
├── README.md               # Este arquivo
│
├── app/                    # Frontend
│   ├── index.html          # Interface principal
│   └── Dockerfile          # Docker do frontend
│
└── backend/                # Backend Flask
    ├── app.py              # Aplicação principal
    ├── requirements.txt    # Dependências Python
    ├── Dockerfile          # Docker do backend
    ├── create_user.py      # Script para criar usuários
    ├── reset_admin.py      # Script para resetar admin
    └── test_login.py       # Script para testar login
```

## 🔧 **Comandos Úteis**

### Gerenciamento de Containers
```bash
# Iniciar aplicação
docker-compose up -d

# Parar aplicação
docker-compose down

# Ver logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild após mudanças
docker-compose down
docker-compose up -d --build
```

### Gerenciamento de Usuários
```bash
# Criar novo usuário
cd backend
python3 create_user.py NOME_USUARIO --generate-password

# Resetar usuário admin
python3 reset_admin.py

# Testar login
python3 test_login.py
```

### Verificar Banco de Dados
```bash
cd backend
python3 check_db.py
```

## 🐛 **Solução de Problemas**

### Login não funciona
1. Verifique se o usuário existe: `python3 check_db.py`
2. Teste a autenticação: `python3 test_login.py`
3. Verifique os logs: `docker-compose logs backend`
4. Confirme que o `.env` está configurado corretamente

### Aplicação volta para login após ações
1. Verifique se `FLASK_ENV=development` no `.env`
2. Confirme que `SESSION_COOKIE_SECURE=false`
3. Verifique se `ALLOWED_ORIGINS=*` ou inclui seu domínio
4. Reinicie os containers: `docker-compose down && docker-compose up -d`

### Erro de CORS
1. Verifique `ALLOWED_ORIGINS` no `.env`
2. Confirme que o frontend está apontando para o backend correto
3. Verifique se não há bloqueio de cookies no navegador

## 📝 **Funcionalidades**

- 🔐 **Sistema de Login Seguro**
- 📝 **Criação e Edição de Cifras**
- 📋 **Gerenciamento de Setlists**
- 🔍 **Busca e Filtros**
- 👥 **Múltiplos Usuários**
- 🎵 **Suporte a Diferentes Tons**

## 🤝 **Contribuição**

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 **Licença**

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 🆘 **Suporte**

Se você encontrar problemas ou tiver dúvidas:
1. Verifique a seção "Solução de Problemas" acima
2. Abra uma issue no GitHub
3. Consulte os logs da aplicação