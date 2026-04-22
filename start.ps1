# ─── CuidaTusLukas Backend — Script de arranque ───────────────────────────────
# Ejecutar con: .\start.ps1
# Requiere: Java 17, Maven, MySQL corriendo en localhost:3306
#
# Las API keys se cargan desde application-local.yml (gitignored).
# Para agregar keys manuales, descomenta las líneas correspondientes:
#
# $env:DB_USERNAME               = "root"
# $env:DB_PASSWORD               = "tu-password"
# $env:CMF_API_KEY               = "tu-api-key-cmf"
# $env:WHOIS_API_KEY             = "tu-api-key-whoisxml"
# $env:GOOGLE_SAFE_BROWSING_KEY  = "tu-api-key-google"
# $env:VIRUSTOTAL_API_KEY        = "tu-api-key-virustotal"

Write-Host "Iniciando CuidaTusLukas Backend en puerto 8080 (perfil: local)..." -ForegroundColor Cyan

mvn spring-boot:run -Dspring-boot.run.profiles=local
