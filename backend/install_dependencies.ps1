# Script PowerShell para instalar dependências do ChordChart Pro
# Útil para executar scripts fora do Docker

Write-Host "🔧 Instalando dependências do ChordChart Pro..." -ForegroundColor Green

# Verificar se pip está instalado
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python não encontrado. Instale o Python primeiro." -ForegroundColor Red
    exit 1
}

# Instalar dependências do requirements.txt
Write-Host "📦 Instalando dependências Python..." -ForegroundColor Yellow
python -m pip install -r requirements.txt

Write-Host "✅ Dependências instaladas com sucesso!" -ForegroundColor Green
Write-Host ""
Write-Host "🔧 Agora você pode executar:" -ForegroundColor Cyan
Write-Host "   python create_user.py admin --generate-password" -ForegroundColor White
Write-Host ""
Write-Host "📋 Ou usar a versão standalone:" -ForegroundColor Cyan
Write-Host "   python create_user_standalone.py admin --generate-password" -ForegroundColor White 