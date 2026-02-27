#!/bin/bash
# Script di Deploy per sso-gateway
set -euo pipefail

# --- CONFIGURAZIONE ---
REMOTE_USER="master"               # Cambia con il tuo utente sul server
REMOTE_HOST="1.2.3.4"              # Cambia con l'IP del tuo server
REMOTE_DEST="/opt/sso-gateway"             # Cambia con il percorso sul server
# ----------------------

echo "--- sso-gateway: Inizio Deploy verso ${REMOTE_HOST} ---"

# 1. Sincronizzazione file (escludendo file inutili)
echo "[1/4] Sincronizzazione file..."
rsync -avz --delete \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '.git/' \
    --exclude '.DS_Store' \
    --exclude 'auth.db' \
    --exclude '.env' \
    ./ ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DEST}/

# 2. Setup ambiente remoto via SSH
echo "[2/4] Setup ambiente virtuale e dipendenze..."
ssh ${REMOTE_USER}@${REMOTE_HOST} << EOF
    cd ${REMOTE_DEST}
    
    # Crea l'ambiente virtuale se non esiste
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        echo "Ambiente virtuale creato."
    fi
    
    # Installa/Aggiorna dipendenze
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Inizializza il database se non esiste
    if [ ! -f "auth.db" ]; then
        export FLASK_APP=run.py
        flask init-db
        echo "Database inizializzato."
    fi
EOF

# 3. Configurazione permessi e log (richiede sudo)
echo "[3/4] Creazione utente e configurazione permessi..."
ssh ${REMOTE_USER}@${REMOTE_HOST} << EOF
    # Crea l'utente di sistema sso-gateway se non esiste
    if ! id "sso-gateway" &>/dev/null; then
        sudo useradd -r -s /bin/false sso-gateway
        echo "Utente di sistema 'sso-gateway' creato."
    fi
    
    # Aggiunge l'utente sso-gateway al gruppo www-data (per il socket)
    sudo usermod -a -G www-data sso-gateway

    # Crea directory log e imposta permessi
    sudo mkdir -p /var/log/sso-gateway
    sudo chown -R sso-gateway:www-data /var/log/sso-gateway
    sudo chmod -R 775 /var/log/sso-gateway

    # Imposta permessi sulla cartella dell'applicazione
    sudo chown -R sso-gateway:www-data ${REMOTE_DEST}
    # Assicura che l'utente master possa ancora scrivere per i prossimi rsync
    sudo chmod -R 775 ${REMOTE_DEST}
EOF

# 4. Riavvio dei servizi
echo "[4/4] Riavvio Gunicorn e Nginx..."
ssh ${REMOTE_USER}@${REMOTE_HOST} << EOF
    # Copia il file di servizio systemd
    sudo cp ${REMOTE_DEST}/deploy/sso-gateway.service /etc/systemd/system/sso-gateway.service
    
    # Riavvia systemd e abilita il servizio
    sudo systemctl daemon-reload
    sudo systemctl enable sso-gateway
    sudo systemctl restart sso-gateway
    
    # Verifica stato servizio
    systemctl is-active --quiet sso-gateway && echo "Servizio sso-gateway attivo! ✅" || echo "ERRORE: Servizio sso-gateway fallito. ❌"
    
    # Riavvia Nginx per sicurezza (opzionale)
    # sudo systemctl reload nginx
EOF

echo "--- Deploy sso-gateway Completato! ---"
echo "Ricorda di configurare il file .env sul server in ${REMOTE_DEST}/.env"
echo "Puoi usare test_radius.py sul server per verificare RADIUS."
