#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# SanWD v8 – Dev-Umgebung Setup
# Ausführen auf k8s-master-01 im Verzeichnis /root/sanwd-v8/
# ═══════════════════════════════════════════════════════════════════
set -e

cd /root/sanwd-v8

echo "🧹 1. Aufräumen (.bak-Dateien entfernen)..."
rm -f src/backend/routes/pdf.js.bak
rm -f src/backend/routes/vorgaenge.js.bak
rm -f src/frontend/src/App.jsx.bak
rm -f src/frontend/src/App.jsx.v67-backup

echo "📋 2. .dockerignore erstellen..."
cat > .dockerignore << 'DEOF'
node_modules
*.tar
*.tar.gz
.git
.env
*.md
deploy.sh
data/
DEOF

echo "🐳 3. docker-compose.yml erstellen..."
cat > docker-compose.yml << 'DEOF'
version: "3.8"
services:
  sanwd:
    build: .
    ports:
      - "127.0.0.1:3088:3000"
    volumes:
      - ./data:/data
    environment:
      - NODE_ENV=development
      - DEV_AUTH=true
      - DATABASE_PATH=/data/sanwd.db
      - SESSION_SECRET=dev-secret-v8-sanwd
    restart: unless-stopped
DEOF

echo "📝 4. .env.example erstellen..."
cat > .env.example << 'DEOF'
# === SanWD v8 Konfiguration ===

# Betriebsmodus
NODE_ENV=production

# Datenbank
DATABASE_PATH=/data/sanwd.db

# Session
SESSION_SECRET=<zufälliger-string-hier>

# === Authentifizierung ===
# Für Entwicklung: DEV_AUTH=true (kein Keycloak nötig)
# Für Produktion: DEV_AUTH weglassen + OIDC konfigurieren
# DEV_AUTH=true

# OIDC / Keycloak
OIDC_ISSUER=https://auth.example.com/realms/myrealm
OIDC_CLIENT_ID=sanwd
OIDC_CLIENT_SECRET=<secret>
OIDC_REDIRECT_URI=https://sanwd.example.com/auth/callback
APP_URL=https://sanwd.example.com

# Optional: Notfall-Passwort (SHA256-Hash)
# EMERGENCY_PASSWORD_HASH=<sha256-hash>
DEOF

echo "📂 5. data-Verzeichnis erstellen..."
mkdir -p data

echo ""
echo "═══════════════════════════════════════════════"
echo "✅ Setup abgeschlossen!"
echo ""
echo "Nächste Schritte:"
echo "  1. auth.js wurde separat bereitgestellt → bitte kopieren"
echo "  2. docker compose build --no-cache"
echo "  3. docker compose up -d"
echo "  4. Browser: http://k8s-master-01:3088"
echo "     → Dev-Login-Seite mit Rollen-/BC-Auswahl"
echo ""
echo "Git-Commit:"
echo "  git add -A && git commit -m 'setup: Docker Compose Dev + DEV_AUTH'"
echo "═══════════════════════════════════════════════"
