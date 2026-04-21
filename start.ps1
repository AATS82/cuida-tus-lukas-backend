# ─── CuidaTusLukas Backend — Script de arranque ───────────────────────────────
# Ejecutar con: .\start.ps1
# Requiere: Java 17, Maven, MySQL corriendo en localhost:3306

# Opcional: sobreescribir credenciales de BD (por defecto usa application.yml)
# $env:DB_USERNAME = "root"
# $env:DB_PASSWORD = "tu-password"

# Opcional: activar verificación en tiempo real con APIs externas
# $env:CMF_API_KEY   = "tu-api-key-cmf"      # gratis en api.cmfchile.cl
# $env:WHOIS_API_KEY = "tu-api-key-whoisxml"  # 500/mes gratis en whoisxmlapi.com

Write-Host "Iniciando CuidaTusLukas Backend en puerto 8080..." -ForegroundColor Cyan

mvn spring-boot:run
