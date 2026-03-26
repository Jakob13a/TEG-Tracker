# TEG Tracker – Render.com Deployment

## Setup auf Render.com

1. Dieses Repository auf GitHub pushen
2. Auf [render.com](https://render.com) anmelden
3. **New → Web Service** → GitHub Repo verbinden
4. Einstellungen:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2`
   - **Environment Variables:**
     - `TEGTRACKER_SECRET_KEY` → beliebiger langer zufälliger String
     - `TEGTRACKER_ADMIN_PASSWORD` → dein Admin-Passwort
5. Deploy klicken

## Login

- **Benutzername:** `admin`
- **Passwort:** wie in der Umgebungsvariable `TEGTRACKER_ADMIN_PASSWORD` gesetzt

## Hinweis zur Datenbank

Die `spieler.db` ist direkt im Repository und enthält die Daten aus dem letzten Backup.
Render verwendet ein **ephemeres Dateisystem** — Änderungen an der DB gehen beim nächsten Deploy verloren.
Für persistente Daten: Render Disk einrichten (kostenpflichtig) oder regelmäßig die DB aus dem Backup-Ordner exportieren.
