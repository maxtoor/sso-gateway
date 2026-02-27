import os
import sys
from dotenv import load_dotenv

# Carica le variabili dal file .env se presente
load_dotenv()

try:
    from radius_eap_mschapv2_client.client import EAPMSCHAPv2Client
except ImportError:
    print("ERRORE: La libreria 'radius-eap-mschapv2-client' non è installata.")
    print("Esegui: pip install radius-eap-mschapv2-client")
    sys.exit(1)

def test_radius():
    # Preleva la configurazione dalle variabili d'ambiente (o usa default per test)
    server = os.getenv("RADIUS_SERVER", "127.0.0.1")
    port = int(os.getenv("RADIUS_PORT", "1812"))
    secret = os.getenv("RADIUS_SECRET", "testing123")
    timeout = int(os.getenv("RADIUS_TIMEOUT", "5"))
    nas_id = os.getenv("RADIUS_NAS_ID", "SSO-Gateway-Test-Client")
    nas_ip = os.getenv("RADIUS_NAS_IP", "127.0.0.1")

    print(f"--- SSO Gateway: Test RADIUS EAP-MSCHAPv2 ---")
    print(f"Server: {server}:{port}")
    print(f"NAS Identifier: {nas_id}")
    print(f"-------------------------------------")

    # Chiede le credenziali interattivamente per il test
    user = input("Inserisci username (es. utente@ente.it): ").strip()
    password = input("Inserisci password: ").strip()

    if not user or not password:
        print("Errore: Username e password sono obbligatori per il test.")
        return

    client = EAPMSCHAPv2Client(
        server=server,
        shared_secret=secret,
        username=user,
        password=password,
        port=port,
        timeout=timeout,
        nas_identifier=nas_id,
        nas_ip_address=nas_ip
    )

    try:
        print("\nInvio richiesta Access-Request (EAP-MSCHAPv2)...")
        if client.authenticate():
            print(">>> RISULTATO: AUTENTICAZIONE RIUSCITA! ✅")
        else:
            print(">>> RISULTATO: AUTENTICAZIONE FALLITA. ❌")
            print("Verifica credenziali, shared secret e abilitazione del client su FreeRADIUS.")
    except Exception as e:
        print(f"\n>>> ERRORE DURANTE IL TEST: {e}")

if __name__ == "__main__":
    test_radius()
