# sso-gateway

Applicazione Flask per autenticare utenti con:
- LDAP esistente (prima scelta)
- RADIUS / eduroam (EAP-MSCHAPv2)
- file SQL locale (SQLite) come fallback

Con auto-registrazione locale consentita ai domini configurati (`REGISTER_ALLOWED_DOMAINS`), oppure a **qualsiasi dominio** con `REGISTER_ALLOW_ANY_DOMAIN=true`.

Puoi usarla come "gateway auth" davanti a pagine WordPress servite da `nginx + apache`.

## 1) Setup rapido

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Configura `.env` con i parametri del tuo LDAP.

## 2) Inizializzazione DB

```bash
export FLASK_APP=run.py
flask init-db
```

Questo crea `auth.db` locale (SQLite).

## 3) Avvio locale

```bash
flask run --host 0.0.0.0 --port 5000
```

Endpoint utili:
- `GET/POST /auth/login`
- `GET/POST /auth/register`
- `GET /auth/confirm-email/<token>`
- `GET /auth/check` (usato da nginx `auth_request`)
- `POST /auth/logout`
- `GET /auth/me` (debug)
- `GET /auth/admin/users` (pannello admin locale)

## 4) Regole di autenticazione implementate

1. Login: prima tenta LDAP.
2. Se LDAP fallisce, tenta RADIUS / eduroam (se abilitato).
3. Se anche RADIUS fallisce, tenta utente locale SQLite.
4. Registrazione locale: ammessa solo con email dei domini configurati in `REGISTER_ALLOWED_DOMAINS` (oppure qualunque dominio se `REGISTER_ALLOW_ANY_DOMAIN=true`).
4. Per utenti locali, l'email diventa anche username.
5. La password locale deve avere almeno 8 caratteri con almeno un numero e un carattere speciale.
6. Nuovi utenti locali ricevono email con link di conferma.
7. Finche' l'email non e' confermata, il login locale e' bloccato.
8. Dopo conferma email, l'utente resta in stato "in attesa" finche' un admin non approva.
9. Gli admin possono creare utenze locali dal pannello `/auth/admin/users`.
10. Gli admin possono approvare, disabilitare/riabilitare o eliminare utenze locali dal pannello `/auth/admin/users`.
11. Gli admin possono salvare note amministrative per ogni utenza locale.
12. Utenti LDAP validati vengono sincronizzati in tabella locale (`source=ldap`).
13. Utenti RADIUS validati vengono sincronizzati in tabella locale (`source=radius`).

## 4.1) Creazione admin iniziale

Dopo `flask init-db`, crea almeno un amministratore:

```bash
export FLASK_APP=run.py
flask create-admin
```

L'admin locale viene creato con identificativo email (`username=email`) e puo' entrare in `/auth/admin/users` per approvare o eliminare account locali.

## 4.2) Modifica credenziali admin

Per aggiornare un amministratore esistente (username, email e/o password):

```bash
export FLASK_APP=run.py
flask change-admin
```

Il comando richiede:
- `Username o email admin attuale`
- `Nuovo username` (invio = invariato)
- `Nuova email` (invio = invariata)
- `Nuova password` (invio = invariata)

Note:
- l'utente deve essere gia' admin (`is_admin=true`);
- username ed email vengono validati per evitare duplicati;
- al termine l'utente resta admin attivo/approvato/con email confermata.

## 5) Integrazione Nginx davanti a WordPress

Esempio base (adatta host/porte):

```nginx
server {
    listen 80;
    server_name wp.example.org;

    # Endpoint interno per il controllo auth
    location = /_auth_check {
        internal;
        proxy_pass http://127.0.0.1:5000/auth/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Cookie $http_cookie;
    }

    # Pagina login servita da Flask
    location /auth/ {
        proxy_pass http://127.0.0.1:5000/auth/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Area WordPress protetta
    location / {
        auth_request /_auth_check;
        error_page 401 = @auth_redirect;

        proxy_pass http://127.0.0.1:8080; # Apache+WP
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location @auth_redirect {
        return 302 /auth/login?next=$request_uri;
    }
}
```

Configurazione pronta:
- `deploy/nginx-location.conf` contiene le location complete `/sso-*` per socket Gunicorn.

## 6) Note produzione (Ubuntu 20.04)

- Usa Gunicorn + systemd per Flask.
- Imposta `FLASK_SECRET_KEY` robusta.
- Metti HTTPS (Let's Encrypt) su Nginx.
- Se LDAP usa certificato interno, configura trust CA del sistema.

Esempio avvio Gunicorn:

```bash
gunicorn -w 3 -b 127.0.0.1:5000 wsgi:app
```

## 7) Sicurezza applicata

- CSRF abilitato su tutti i form `POST` tramite `Flask-WTF`.
- Rate limit applicativo su endpoint login e suggerimenti utente.
- Cookie di sessione/remember con policy `HttpOnly` e `SameSite` configurabili.

Miglioramenti ancora consigliati:
- Audit log accessi/failed login.
- Rate limit anche a livello Nginx/WAF.

## 8) Configurazione email (SMTP)

Per inviare:
- link conferma all'utente in registrazione
- avviso all'amministratore solo dopo conferma email utente

imposta in `.env`:

```env
MAIL_ENABLED=true
MAIL_HOST=smtp.example.org
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=utente_smtp
MAIL_PASSWORD=password_smtp
MAIL_FROM=no-reply@example.org
ADMIN_NOTIFY_EMAIL=admin@example.org
LOGO_URL=https://example.org/path/logo.png
APP_BASE_URL=https://tuo-dominio.it
PUBLIC_LOGIN_PATH=/sso-login
PUBLIC_REGISTER_PATH=/sso-register
PUBLIC_ADMIN_USERS_PATH=/sso
PUBLIC_CONFIRM_EMAIL_PREFIX=/sso-confirm-email
PUBLIC_SUGGEST_PATH=/sso-suggest-users
PUBLIC_LOGOUT_PATH=/sso-logout
LOGIN_SUGGEST_ENABLED=true
LOGIN_SUGGEST_MIN_CHARS=3
LOGIN_SUGGEST_RATE_LIMIT_PER_MIN=120
LOGIN_SUGGEST_LDAP_ENABLED=true
LDAP_SUGGEST_FILTER=(uid={query}*)
EMAIL_CONFIRM_MAX_AGE_SECONDS=86400
```

Con path custom Nginx, esponi anche il suggeritore login:

```nginx
location = /sso-suggest-users {
    auth_request off;
    proxy_pass http://unix:/run/sso-gateway/gunicorn.sock:/auth/suggest-users;
    proxy_set_header Cookie $http_cookie;
    proxy_set_header Host $host;
}
```

## 9) Configurazione RADIUS (eduroam)

Per abilitare l'autenticazione federata tramite FreeRADIUS (EAP-MSCHAPv2):

1. Imposta in `.env`:
   ```env
   RADIUS_ENABLED=true
   RADIUS_SERVER=1.2.3.4
   RADIUS_PORT=1812
   RADIUS_SECRET=la_tua_shared_secret
   RADIUS_NAS_ID=SSO-Gateway
   ```
2. Verifica la connettività dal server verso il RADIUS utilizzando lo script di test:
   ```bash
   source .venv/bin/activate
   python3 test_radius.py
   ```
   Lo script caricherà le impostazioni dal file `.env` e chiederà username e password per simulare un login reale.

3. Assicurati che l'indirizzo IP del server SSO Gateway sia autorizzato nel file `clients.conf` del tuo server FreeRADIUS.

## 10) Deploy sul Server (Linux)

Il progetto include uno script `deploy.sh` per automatizzare l'installazione in `/opt/sso-gateway`.

1. **Configurazione locale**:
   Modifica le variabili in `deploy.sh` sul tuo Mac:
   ```bash
   REMOTE_USER="tuo_utente"
   REMOTE_HOST="ip_del_server"
   REMOTE_DEST="/opt/sso-gateway"
   ```

2. **Esecuzione Deploy**:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```

Lo script si occuperà di sincronizzare i file, creare l'ambiente virtuale, configurare l'utente di sistema `sso-gateway` e avviare il servizio.

## 11) Gestione Servizio (Systemd)

L'applicazione gira come servizio di sistema isolato.

- **Utente**: `sso-gateway` (senza shell di login)
- **Gruppo**: `www-data`
- **Socket**: `/run/sso-gateway/gunicorn.sock` (permessi 0770)

### Comandi utili sul server:

```bash
# Visualizzare i log dell'applicazione
sudo tail -f /var/log/sso-gateway/error.log

# Controllare lo stato del servizio
sudo systemctl status sso-gateway

# Riavviare l'applicazione
sudo systemctl restart sso-gateway
```

## 12) Licenza

Questo progetto e' distribuito sotto licenza **GNU General Public License v3.0**.
Vedi file `LICENSE`.
