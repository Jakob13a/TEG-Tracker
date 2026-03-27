from flask import Flask, render_template, request, redirect, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from datetime import datetime, timedelta, date, timezone

# Register date adapter for SQLite to avoid deprecation warnings
sqlite3.register_adapter(date, lambda d: d.isoformat())
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import json
import threading
import time
import logging
import os
import shutil

app = Flask(__name__)
# Sicherheitskonfiguration für Sessions
app.secret_key = os.environ.get('TEGTRACKER_SECRET_KEY', os.urandom(64).hex())
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spieler.db'))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------- DATABASE ----------------

# Erhöhe SQLite Timeout und aktiviere WAL-Mode
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def retry_db_operation(func, max_retries=5):
    """Retry database operation with exponential backoff on lock"""
    for attempt in range(max_retries):
        try:
            return func()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 0.1  # Exponential backoff: 0.1, 0.2, 0.4, 0.8, 1.6 seconds
                time.sleep(wait_time)
                continue
            raise

def init_db():
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    # On Railway: seed from bundled DB if volume is empty
    seed = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spieler.db')
    if not os.path.exists(DATABASE) and os.path.exists(seed) and DATABASE != seed:
        import shutil as _shutil
        _shutil.copy(seed, DATABASE)
        print(f"Seeded database from {seed} to {DATABASE}")
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )
    """)
    # ensure role column exists for older DBs
    c.execute("PRAGMA table_info(users)")
    existing = [r[1] for r in c.fetchall()]
    if 'role' not in existing:
        try:
            c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except sqlite3.OperationalError:
            pass

    c.execute("""
    CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE,
        name TEXT,
        type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        input_order INTEGER DEFAULT 2147483647
    )
    """)

    # ensure input_order column exists for backward compatibility
    c.execute("PRAGMA table_info(players)")
    player_cols = [r[1] for r in c.fetchall()]
    if 'input_order' not in player_cols:
        c.execute("ALTER TABLE players ADD COLUMN input_order INTEGER DEFAULT 2147483647")

    c.execute("""
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_uuid TEXT,
        date TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS name_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_uuid TEXT,
        old_name TEXT,
        new_name TEXT,
        changed_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS daily_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE,
        total_players INTEGER,
        active_players INTEGER,
        inactive_players INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        login_time TEXT,
        logout_time TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS deleted_players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE,
        name TEXT,
        type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        deleted_at TEXT,
        deleted_by TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS former_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE,
        name TEXT,
        type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        moved_to_former TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS user_preferences (
        user_id INTEGER PRIMARY KEY,
        theme TEXT DEFAULT 'dark',
        dashboard_layout TEXT DEFAULT 'default',
        notifications INTEGER DEFAULT 1
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS dashboard_widgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        widget_name TEXT,
        enabled INTEGER DEFAULT 1,
        position INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

init_db()
# ensure an admin account exists with known credentials

def ensure_admin():
    conn = get_db_connection()
    c = conn.cursor()
    # Admin-Passwort aus Umgebungsvariable für sichere Konfiguration, Fallback nur für lokalen Test
    admin_password = os.environ.get('TEGTRACKER_ADMIN_PASSWORD', 'Jack9177?')
    pwd_hash = generate_password_hash(admin_password)

    c.execute("SELECT id FROM users WHERE username='admin'")
    row = c.fetchone()
    if row:
        c.execute("UPDATE users SET role='admin', password=? WHERE username='admin'", (pwd_hash,))
    else:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
                  ('admin', pwd_hash))
    conn.commit()
    conn.close()

ensure_admin()


# ---------------- LOGIN ----------------

class User(UserMixin):
    def __init__(self, id, username=None, role='user'):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    # fetch username/role so we can make decisions later
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, role FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        username, role = row
        return User(user_id, username=username, role=role)
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, password, role FROM users WHERE username=?", (username,))
        row = c.fetchone()

        if row and check_password_hash(row[1], password):
            user_id = row[0]
            user_role = row[2] if len(row) > 2 else 'user'
            # Logge Login in der Tabelle
            login_time = datetime.now(timezone.utc).isoformat()
            c.execute("""
            INSERT INTO login_history (user_id, username, login_time)
            VALUES (?, ?, ?)
            """, (user_id, username, login_time))
            conn.commit()
            conn.close()
            
            login_user(User(user_id, username=username, role=user_role))
            return redirect("/")
        
        conn.close()

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    username = current_user.username
    
    # Logge Logout in der Tabelle (letzter Eintrag ohne logout_time)
    conn = get_db_connection()
    c = conn.cursor()
    logout_time = datetime.now(timezone.utc).isoformat()
    c.execute("""
    UPDATE login_history 
    SET logout_time = ? 
    WHERE user_id = ? AND logout_time IS NULL 
    ORDER BY login_time DESC LIMIT 1
    """, (logout_time, user_id))
    conn.commit()
    conn.close()
    
    logout_user()
    return redirect("/login")


# ---------------- HELPER ----------------


def get_uuid(name):
    url = f"https://api.mojang.com/users/profiles/minecraft/{name}"
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()["id"]
    return None


def get_user_theme(user_id):
    """Hole das Theme eines Benutzers"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT theme FROM user_preferences WHERE user_id=?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else 'dark'


def save_user_theme(user_id, theme):
    """Speichere das Theme eines Benutzers"""
    def _save():
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        INSERT OR REPLACE INTO user_preferences (user_id, theme)
        VALUES (?, ?)
        """, (user_id, theme))
        conn.commit()
        conn.close()

    retry_db_operation(_save)


def get_dashboard_widgets(user_id):
    """Hole Dashboard-Widget-Konfiguration"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    SELECT widget_name, enabled FROM dashboard_widgets 
    WHERE user_id=? ORDER BY position
    """, (user_id,))
    widgets = c.fetchall()
    conn.close()
    
    if not widgets:
        # Initialisiere Default Widgets
        default_widgets = ['stats', 'list', 'trends', 'top10', 'patterns']
        conn = get_db_connection()
        c = conn.cursor()
        for i, widget in enumerate(default_widgets):
            c.execute("""
            INSERT INTO dashboard_widgets (user_id, widget_name, enabled, position)
            VALUES (?, ?, 1, ?)
            """, (user_id, widget, i))
        conn.commit()
        conn.close()
        return [(w, 1) for w in default_widgets]
    
    return widgets


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        if not check_password_hash(get_user_password(current_user.id), old):
            return render_template('change_password.html', error='Altes Passwort falsch.')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('UPDATE users SET password=? WHERE id=?',
                  (generate_password_hash(new), current_user.id))
        conn.commit()
        conn.close()
        return render_template('change_password.html', message='Passwort geändert.')
    return render_template('change_password.html')


def get_user_password(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ''


@app.route('/users', methods=['GET','POST'])
@login_required
def users_list():
    if current_user.role != 'admin':
        return redirect('/')

    conn = get_db_connection()
    c = conn.cursor()

    # handle admin actions
    if request.method == 'POST':
        action = request.form.get('action')
        target_id = request.form.get('user_id')
        if action == 'toggle_role':
            c.execute('SELECT role FROM users WHERE id=?', (target_id,))
            cur_role = c.fetchone()[0]
            new_role = 'admin' if cur_role != 'admin' else 'user'
            c.execute('UPDATE users SET role=? WHERE id=?', (new_role, target_id))
        elif action == 'delete':
            c.execute('DELETE FROM users WHERE id=?', (target_id,))
        conn.commit()

    c.execute('SELECT id, username, role FROM users')
    rows = c.fetchall()
    conn.close()
    return render_template('users.html', users=rows)


@app.route('/login-history')
@login_required
def login_history():
    if current_user.role != 'admin':
        return redirect('/')
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
    SELECT id, user_id, username, login_time, logout_time 
    FROM login_history 
    ORDER BY login_time DESC 
    LIMIT 500
    """)
    history = c.fetchall()
    conn.close()
    
    # Formatiere die Daten für das Template
    sessions = []
    for session_id, user_id, username, login_time, logout_time in history:
        login_dt = datetime.fromisoformat(login_time)
        
        session_info = {
            "username": username,
            "login_time": login_dt.strftime("%d.%m.%Y %H:%M:%S"),
            "logout_time": None,
            "duration": None
        }
        
        if logout_time:
            logout_dt = datetime.fromisoformat(logout_time)
            session_info["logout_time"] = logout_dt.strftime("%d.%m.%Y %H:%M:%S")
            duration = logout_dt - login_dt
            hours = duration.seconds // 3600
            minutes = (duration.seconds % 3600) // 60
            session_info["duration"] = f"{int(duration.days)}d {hours}h {minutes}m" if duration.days > 0 else f"{hours}h {minutes}m"
        
        sessions.append(session_info)
    
    return render_template('login_history.html', sessions=sessions)


def parse_date(text):
    today = date.today()
    text = text.lower()

    if "heute" in text:
        return today
    if "gestern" in text:
        return today - timedelta(days=1)
    if "vorgestern" in text:
        return today - timedelta(days=2)

    if "vor" in text and "tag" in text:
        try:
            days = int(text.split("vor")[1].split("tag")[0].strip())
            return today - timedelta(days=days)
        except:
            return today

    return today


# ---------------- DISCORD WEBHOOK ----------------

def get_webhook_url():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='discord_webhook'")
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def save_webhook_url(url):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM settings WHERE key='discord_webhook'")
    c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("discord_webhook", url))
    conn.commit()
    conn.close()

def get_player_status_color(days_offline):
    if days_offline <= 7:
        return 0x22c55e  # Grün - Aktiv
    elif days_offline <= 21:
        return 0xfbbf24  # Gelb - Warnung
    else:
        return 0xef4444  # Rot - Kritisch

def get_player_status(days_offline):
    if days_offline <= 7:
        return "✅ Aktiv"
    elif days_offline <= 21:
        return "⚠️ Warnung"
    else:
        return "❌ Kritisch"

import io
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

def backup_database():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"backup_{timestamp}.db")
    shutil.copy(DATABASE, backup_path)
    print(f"Database backup created: {backup_path}")

def send_discord_embeds(players_data):
    webhook_url = get_webhook_url()
    if not webhook_url:
        return False
    
    try:
        today = datetime.now(timezone.utc).date()
        total = len(players_data)
        active = sum(1 for p in players_data if p["days_offline"] <= 7)
        warning = sum(1 for p in players_data if 7 < p["days_offline"] <= 21)
        critical = sum(1 for p in players_data if p["days_offline"] > 21)
        
        # Erstelle Embed mit Statistiken
        stats_embed = {
            "title": "📊 Spieler Report",
            "color": 0x3b82f6,
            "fields": [
                {"name": "Gesamt Spieler", "value": str(total), "inline": True},
                {"name": "✅ Aktiv (≤7 Tage)", "value": str(active), "inline": True},
                {"name": "⚠️ Warnung (8-21 Tage)", "value": str(warning), "inline": True},
                {"name": "❌ Kritisch (>21 Tage)", "value": str(critical), "inline": True},
                {"name": "📅 Erstellt", "value": f"<t:{int(datetime.now().timestamp())}:d>", "inline": False}
            ],
            "timestamp": datetime.now().isoformat()
        }

        # Füge Trenddaten (letzte 7 Tage) hinzu
        weekly = get_weekly_trends()
        chart_bytes = None
        if weekly:
            # nur die letzten 7 Tage für Übersicht
            last7 = weekly[-7:]
            dates = [d['date'] for d in last7]
            totals = [d['total'] for d in last7]
            actives = [d['active'] for d in last7]
            inactives = [d['inactive'] for d in last7]

            if plt:
                # matplotlib chart
                plt.clf()
                plt.plot(dates, totals, label='Gesamt', color='#3b82f6', marker='o')
                plt.plot(dates, actives, label='Aktiv', color='#22c55e', marker='o')
                plt.plot(dates, inactives, label='Inaktiv', color='#ef4444', marker='o')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.legend()
                plt.title('Spieler-Trends (letzte 7 Tage)')
                buf = io.BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                chart_bytes = buf.read()
                buf.close()

            # always create embed, include image only if chart_bytes available
            trend_embed = {
                "title": "📈 Trends (letzte 7 Tage)",
                "color": 0x3b82f6,
                "timestamp": datetime.now().isoformat()
            }
            if chart_bytes:
                trend_embed["image"] = {"url": "attachment://trends.png"}
            embeds = [stats_embed, trend_embed]
        else:
            embeds = [stats_embed]
        
        # Sortiere Spieler nach Status
        players_by_status = {
            "aktiv": [p for p in players_data if p["days_offline"] <= 7],
            "warnung": [p for p in players_data if 7 < p["days_offline"] <= 21],
            "kritisch": [p for p in players_data if p["days_offline"] > 21]
        }
        
        
        # Erstelle Embeds für jeden Status
        for status, players in players_by_status.items():
            if not players:
                continue
            
            color_map = {"aktiv": 0x22c55e, "warnung": 0xfbbf24, "kritisch": 0xef4444}
            status_titles = {"aktiv": "✅ Aktive Spieler", "warnung": "⚠️ Warnung", "kritisch": "❌ Kritisch"}
            
            # Splitte in Chunks von max 20 Spielern pro Embed
            for i in range(0, len(players), 20):
                chunk = players[i:i+20]
                player_text = "\n".join([
                    f"**{p['name']}** - {p['days_offline']}d ({p['last_seen']})"
                    for p in chunk
                ])
                
                embed = {
                    "title": f"{status_titles[status]} ({len(chunk)})",
                    "color": color_map[status],
                    "description": player_text,
                    "timestamp": datetime.now().isoformat()
                }
                embeds.append(embed)
        
        # Sende bis zu 10 Embeds pro Message (Discord Limit)
        if chart_bytes:
            # send with attachment to allow image embed
            files = {'file': ('trends.png', chart_bytes, 'image/png')}
            for i in range(0, len(embeds), 10):
                chunk = embeds[i:i+10]
                payload = {
                    "embeds": chunk,
                    "username": "Spieler Tracker Bot"
                }
                response = requests.post(webhook_url, data=payload, files=files)
                if response.status_code != 204:
                    return False
        else:
            for i in range(0, len(embeds), 10):
                chunk = embeds[i:i+10]
                payload = {
                    "embeds": chunk,
                    "username": "Spieler Tracker Bot"
                }
                response = requests.post(webhook_url, json=payload)
                if response.status_code != 204:
                    return False
        
        backup_database()
        return True
    except Exception as e:
        print(f"Discord webhook error: {e}")
        return False

def check_name_changes(uuid, new_name):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT name FROM players WHERE uuid=?", (uuid,))
    result = c.fetchone()
    
    if result:
        old_name = result[0]
        if old_name != new_name:
            c.execute("""
            INSERT INTO name_history (player_uuid, old_name, new_name, changed_at)
            VALUES (?, ?, ?, ?)
            """, (uuid, old_name, new_name, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return True
    
    conn.close()
    return False

def calculate_trends():
    def _do_calculate():
        conn = get_db_connection()
        c = conn.cursor()
        
        today = datetime.now(timezone.utc).date()
        today_str = today.isoformat()
        
        c.execute("SELECT uuid, last_seen FROM players")
        players = c.fetchall()
        
        total = len(players)
        active = 0
        inactive = 0
        
        for uuid, last_seen in players:
            last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
            days = (today - last_seen_date).days
            if days <= 7:
                active += 1
            else:
                inactive += 1
        
        c.execute("INSERT OR REPLACE INTO daily_stats (date, total_players, active_players, inactive_players) VALUES (?, ?, ?, ?)",
                  (today_str, total, active, inactive))
        
        conn.commit()
        conn.close()
    
    retry_db_operation(_do_calculate)

def get_weekly_trends():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Letzten 30 Tage
    today = datetime.now(timezone.utc).date()
    data = []
    
    for i in range(29, -1, -1):
        date = today - timedelta(days=i)
        date_str = date.isoformat()
        
        c.execute("SELECT total_players, active_players, inactive_players FROM daily_stats WHERE date=?", (date_str,))
        result = c.fetchone()
        
        if result:
            total, active, inactive = result
        else:
            total, active, inactive = 0, 0, 0
        
        data.append({
            "date": date_str,
            "total": total,
            "active": active,
            "inactive": inactive
        })
    
    conn.close()
    return data

def get_player_activity_data(uuid):
    """Gibt die Aktivitätsdaten eines Spielers der letzten 30 Tage zurück"""
    conn = get_db_connection()
    c = conn.cursor()
    
    today = datetime.now(timezone.utc).date()
    data = []
    
    for i in range(29, -1, -1):
        date = today - timedelta(days=i)
        date_str = date.isoformat()
        
        c.execute("SELECT COUNT(*) FROM activity WHERE player_uuid=? AND date=?", (uuid, date_str))
        count = c.fetchone()[0]
        
        data.append({
            "date": date_str,
            "active": 1 if count > 0 else 0
        })
    
    conn.close()
    return data


def get_player_activity_patterns():
    """Berechnet die Aktivitätsmuster nach Wochentag"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Wochentage: 0=Montag, 6=Sonntag
    weekday_names = ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"]
    weekday_stats = {i: {"name": name, "count": 0} for i, name in enumerate(weekday_names)}
    
    c.execute("SELECT date FROM activity")
    activities = c.fetchall()
    conn.close()
    
    # Zähle Aktivitäten pro Wochentag
    for (date_str,) in activities:
        try:
            activity_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            weekday = activity_date.weekday()
            weekday_stats[weekday]["count"] += 1
        except:
            pass
    
    return [weekday_stats[i] for i in range(7)]


# ---------------- MAIN ----------------

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    conn = get_db_connection()
    c = conn.cursor()

    # -------- LISTE EINLESEN --------
    warning_message = None
    confirm_needed = False
    last_names = ""

    # handle new list submission with duplicate-day warning
    if request.method == "POST":
        last_names = request.form.get("names", "")
        # check if we already recorded activity today
        today_str = date.today().isoformat()
        c.execute("SELECT 1 FROM activity WHERE date=? LIMIT 1", (today_str,))
        already = c.fetchone() is not None
        if already and not request.form.get("confirm"):
            warning_message = "Heute wurde bereits eine Liste gespeichert. Bitte bestätigen, um trotzdem zu speichern."
            confirm_needed = True
            conn.close()
        else:
            lines = last_names.split("\n")
            new_uuids = set()  # Track all UUIDs from the new list

            for input_order, line in enumerate(lines):
                if not line.strip():
                    continue

                parts = line.split(" ", 1)
                name = parts[0]
                status = parts[1] if len(parts) > 1 else "Heute"
                
                if "über einer woche" in status.lower() or "vor mehr als einer woche" in status.lower():
                    last_seen_date = date.today() - timedelta(days=8)
                else:
                    last_seen_date = parse_date(status)
                
                last_seen = last_seen_date.isoformat()

                if name.startswith("."):
                    player_type = "bedrock"
                    player_uuid = "bedrock_" + name.lower()
                else:
                    player_type = "java"
                    player_uuid = get_uuid(name)
                    if not player_uuid:
                        continue

                new_uuids.add(player_uuid)

                # Check if player is in former_members and restore if found
                c.execute("SELECT uuid FROM former_members WHERE uuid=?", (player_uuid,))
                is_former = c.fetchone() is not None
                
                if is_former:
                    # Move from former_members back to players
                    c.execute("""
                    SELECT uuid, name, type, first_seen, last_seen FROM former_members WHERE uuid=?
                    """, (player_uuid,))
                    former_data = c.fetchone()
                    if former_data:
                        # Check if already in players to avoid duplicate insert
                        c.execute("SELECT uuid FROM players WHERE uuid=?", (player_uuid,))
                        already_in_players = c.fetchone() is not None
                        if not already_in_players:
                            c.execute("""
                            INSERT INTO players (uuid, name, type, first_seen, last_seen)
                            VALUES (?, ?, ?, ?, ?)
                            """, former_data[:5])
                        c.execute("DELETE FROM former_members WHERE uuid=?", (player_uuid,))

                c.execute("SELECT uuid, name, last_seen FROM players WHERE uuid=?", (player_uuid,))
                exists = c.fetchone()

                if exists:
                    existing_last_seen_date = datetime.strptime(exists[2], "%Y-%m-%d").date()
                    candidate_last_seen_date = last_seen_date

                    if "über einer woche" in status.lower() or "vor mehr als einer woche" in status.lower():
                        new_last_seen_date = min(existing_last_seen_date, candidate_last_seen_date)
                    else:
                        new_last_seen_date = max(existing_last_seen_date, candidate_last_seen_date)

                    last_seen_update = new_last_seen_date.isoformat()

                    c.execute("""
                    UPDATE players SET name=?, last_seen=?, input_order=? WHERE uuid=?
                    """, (name, last_seen_update, input_order, player_uuid))
                else:
                    # Neuer Spieler: Verwende das berechnete Datum
                    c.execute("""
                    INSERT INTO players (uuid, name, type, first_seen, last_seen, input_order)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (player_uuid, name, player_type, last_seen, last_seen, input_order))

                c.execute("INSERT INTO activity (player_uuid, date) VALUES (?, ?)",
                          (player_uuid, last_seen))

            # Check for players that are no longer in the new list and move them to former_members
            c.execute("SELECT uuid, name, type, first_seen, last_seen FROM players")
            all_players = c.fetchall()
            
            for player_uuid, name, player_type, first_seen, last_seen in all_players:
                if player_uuid not in new_uuids:
                    # This player is no longer in the new list - move to former_members
                    c.execute("SELECT uuid FROM former_members WHERE uuid=?", (player_uuid,))
                    already_former = c.fetchone() is not None
                    
                    if not already_former:
                        c.execute("""
                        INSERT INTO former_members (uuid, name, type, first_seen, last_seen, moved_to_former)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, (player_uuid, name, player_type, first_seen, last_seen, today_str))
                    
                    c.execute("DELETE FROM players WHERE uuid=?", (player_uuid,))

            conn.commit()
            conn.close()

    # calculate_trends() removed from request path to avoid DB locks;
    # it will be executed periodically in a background thread instead.

    # -------- FILTER & SUCHE --------
    # Open new connection for querying
    conn = get_db_connection()
    c = conn.cursor()
    
    filter_type = request.args.get("filter")
    version_filter = request.args.get("version")
    min_days = request.args.get("min_days")
    max_days = request.args.get("max_days")
    search_query = request.args.get("search", "").lower()

    c.execute("SELECT uuid, name, type, last_seen, first_seen FROM players ORDER BY input_order ASC, name ASC")
    raw_players = c.fetchall()

    today = datetime.now(timezone.utc).date()
    players = []

    for p in raw_players:
        uuid_val, name, p_type, last_seen, first_seen = p
        last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
        days_offline = (today - last_seen_date).days

        # Suchfilter
        if search_query and search_query not in name.lower():
            continue

        if version_filter == "java" and p_type != "java":
            continue
        if version_filter == "bedrock" and p_type != "bedrock":
            continue

        if filter_type == "aktiv" and days_offline > 7:
            continue
        if filter_type == "warnung" and not (7 < days_offline < 21):
            continue
        if filter_type == "kritisch" and days_offline < 21:
            continue

        if min_days:
            if days_offline < int(min_days):
                continue

        if max_days:
            if days_offline > int(max_days):
                continue

        players.append({
            "uuid": uuid_val,
            "name": name,
            "type": p_type,
            "days_offline": days_offline,
            "first_seen": first_seen,
            "last_seen": last_seen
        })

    # Statistiken berechnen
    stats = {
        "total": len(players),
        "aktiv": len([p for p in players if p["days_offline"] <= 7]),
        "warnung": len([p for p in players if 7 < p["days_offline"] <= 21]),
        "kritisch": len([p for p in players if p["days_offline"] > 21])
    }

    conn.close()

    # Hole User-Einstellungen
    theme = get_user_theme(current_user.id)
    widgets = get_dashboard_widgets(current_user.id)

    return render_template("index.html",
                           players=players,
                           stats=stats,
                           search_query=search_query,
                           warning_message=warning_message,
                           confirm_needed=confirm_needed,
                           last_names=last_names,
                           theme=theme,
                           widgets=widgets)


# ---------------- PLAYER DETAIL ----------------

@app.route("/player/<uuid>")
@login_required
def player_detail(uuid):

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT name, first_seen, last_seen, type FROM players WHERE uuid=?", (uuid,))
    player = c.fetchone()

    if not player:
        return redirect("/")

    name, first_seen, last_seen, p_type = player

    c.execute("SELECT date FROM activity WHERE player_uuid=?", (uuid,))
    all_dates = [d[0] for d in c.fetchall()]

    # nur die letzten 30 Tage verwenden
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=29)
    dates = []
    for d in sorted(set(all_dates)):
        try:
            dt = datetime.strptime(d, "%Y-%m-%d").date()
            if start_date <= dt <= today:
                dates.append(d)
        except Exception:
            pass

    # Abrufen der Namensänderungshistorie
    c.execute("""
    SELECT old_name, new_name, changed_at FROM name_history 
    WHERE player_uuid=? 
    ORDER BY changed_at DESC
    """, (uuid,))
    name_changes = c.fetchall()

    conn.close()

    today = datetime.now(timezone.utc).date()
    last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
    days_offline = (today - last_seen_date).days

    return render_template("player.html",
                           uuid=uuid,
                           name=name,
                           first_seen=first_seen,
                           last_seen=last_seen,
                           days_offline=days_offline,
                           dates=dates,
                           p_type=p_type,
                           name_changes=name_changes)


# ---------------- DELETE/RECYCLE ----------------

@app.route("/delete/<uuid>", methods=["POST"])
@login_required
def delete_player(uuid):
    """Verschiebe Spieler in den Papierkorb statt zu löschen"""
    conn = get_db_connection()
    c = conn.cursor()

    # Hole Spielerdaten
    c.execute("SELECT name, type, first_seen, last_seen FROM players WHERE uuid=?", (uuid,))
    player = c.fetchone()
    
    if player:
        name, p_type, first_seen, last_seen = player
        deleted_time = datetime.now(timezone.utc).isoformat()
        deleted_by = current_user.username
        
        # Verschiebe in deleted_players
        c.execute("""
        INSERT INTO deleted_players (uuid, name, type, first_seen, last_seen, deleted_at, deleted_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (uuid, name, p_type, first_seen, last_seen, deleted_time, deleted_by))
        
        # Lösche vom players und activity
        c.execute("DELETE FROM activity WHERE player_uuid=?", (uuid,))
        c.execute("DELETE FROM players WHERE uuid=?", (uuid,))
        
        conn.commit()

    conn.close()

    return redirect("/")


@app.route("/trash")
@login_required
def trash():
    """Admin-only Ansicht des Papierkorbs"""
    if current_user.role != 'admin':
        return redirect('/')

    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
    SELECT uuid, name, type, deleted_at, deleted_by FROM deleted_players 
    ORDER BY deleted_at DESC LIMIT 100
    """)
    deleted_players = c.fetchall()
    conn.close()
    
    players = []
    for uuid, name, p_type, deleted_at, deleted_by in deleted_players:
        try:
            deleted_dt = datetime.fromisoformat(deleted_at)
            deleted_str = deleted_dt.strftime("%d.%m.%Y %H:%M")
        except:
            deleted_str = deleted_at
        
        players.append({
            "uuid": uuid,
            "name": name,
            "type": p_type,
            "deleted_at": deleted_str,
            "deleted_by": deleted_by
        })
    
    return render_template('trash.html', players=players)


@app.route("/restore/<uuid>", methods=["POST"])
@login_required
def restore_player(uuid):
    """Stelle einen Spieler aus dem Papierkorb wieder her"""
    if current_user.role != 'admin':
        return redirect('/')

    conn = get_db_connection()
    c = conn.cursor()
    
    # Hole gelöschte Spielerdaten
    c.execute("SELECT name, type, first_seen, last_seen FROM deleted_players WHERE uuid=?", (uuid,))
    player = c.fetchone()
    
    if player:
        name, p_type, first_seen, last_seen = player
        
        # Füge wieder in players ein
        c.execute("""
        INSERT OR IGNORE INTO players (uuid, name, type, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        """, (uuid, name, p_type, first_seen, last_seen))
        
        # Lösche aus deleted_players
        c.execute("DELETE FROM deleted_players WHERE uuid=?", (uuid,))
        
        conn.commit()

    conn.close()

    return redirect("/trash")


@app.route("/permanent-delete/<uuid>", methods=["POST"])
@login_required
def permanent_delete(uuid):
    """Lösche einen Spieler endgültig"""
    if current_user.role != 'admin':
        return redirect('/')

    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("DELETE FROM deleted_players WHERE uuid=?", (uuid,))
    conn.commit()
    conn.close()

    return redirect("/trash")


# ---------------- FORMER MEMBERS ----------------

@app.route("/former-members")
@login_required
def former_members():
    """Zeige ehemalige Clanmitglieder"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
    SELECT uuid, name, type, moved_to_former FROM former_members 
    ORDER BY moved_to_former DESC
    """)
    former = c.fetchall()
    conn.close()
    
    players = []
    for uuid, name, p_type, moved_to_former in former:
        try:
            moved_dt = datetime.fromisoformat(moved_to_former)
            moved_str = moved_dt.strftime("%d.%m.%Y")
        except:
            moved_str = moved_to_former
        
        players.append({
            "uuid": uuid,
            "name": name,
            "type": p_type,
            "moved_to_former": moved_str
        })
    
    return render_template('former_members.html', players=players)


@app.route("/restore-former/<uuid>", methods=["POST"])
@login_required
def restore_former_member(uuid):
    """Stelle einen ehemaligen Spieler wieder her"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Hole Spielerdaten aus former_members
    c.execute("SELECT name, type, first_seen, last_seen FROM former_members WHERE uuid=?", (uuid,))
    player = c.fetchone()
    
    if player:
        name, p_type, first_seen, last_seen = player
        
        # Füge wieder in players ein
        c.execute("""
        INSERT OR IGNORE INTO players (uuid, name, type, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        """, (uuid, name, p_type, first_seen, last_seen))
        
        # Lösche aus former_members
        c.execute("DELETE FROM former_members WHERE uuid=?", (uuid,))
        
        conn.commit()

    conn.close()

    return redirect("/former-members")


# ---------------- DISCORD WEBHOOK ----------------

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        webhook_url = request.form.get("webhook_url", "").strip()
        if webhook_url:
            save_webhook_url(webhook_url)
        return redirect("/settings")
    
    current_webhook = get_webhook_url()
    return render_template("settings.html", webhook_url=current_webhook)


@app.route("/dashboard-config", methods=["GET", "POST"])
@login_required
def dashboard_config():
    """Admin-only Dashboard Widget Konfiguration"""
    if current_user.role != 'admin':
        return redirect('/')
    
    conn = get_db_connection()
    c = conn.cursor()
    
    if request.method == "POST":
        # Abrufen aller Widget-Namen aus dem Form
        available_widgets = ['stats', 'list', 'trends', 'top10', 'patterns', 'discord']
        
        for widget in available_widgets:
            enabled = request.form.get(f'widget_{widget}') == 'on'
            c.execute("""
            UPDATE dashboard_widgets 
            SET enabled = ? 
            WHERE user_id = ? AND widget_name = ?
            """, (1 if enabled else 0, current_user.id, widget))
        
        conn.commit()
        conn.close()
        return redirect('/dashboard-config')
    
    # Hole aktuelle Widget-Einstellungen
    c.execute("""
    SELECT widget_name, enabled FROM dashboard_widgets 
    WHERE user_id = ? ORDER BY position
    """, (current_user.id,))
    widgets = c.fetchall()
    conn.close()
    
    widget_dict = {w[0]: bool(w[1]) for w in widgets}
    
    # Default Widgets definieren
    available_widgets = {
        'stats': {'name': 'Statistiken', 'icon': '📊', 'description': 'Gesamte Statistiken'},
        'list': {'name': 'Spielerliste', 'icon': '👥', 'description': 'Komplette Spielerliste'},
        'trends': {'name': 'Trends', 'icon': '📈', 'description': 'Wöchentliche Trends'},
        'top10': {'name': 'Top 10', 'icon': '🏆', 'description': 'Top 10 aktivste Spieler'},
        'patterns': {'name': 'Muster', 'icon': '📊', 'description': 'Aktivitätsmuster nach Wochentag'},
        'discord': {'name': 'Discord', 'icon': '💬', 'description': 'Discord Integration'}
    }
    
    for widget_name, config in available_widgets.items():
        config['enabled'] = widget_dict.get(widget_name, True)
    
    return render_template('dashboard_config.html', widgets=available_widgets)


@app.route("/top10")
@login_required
def top10():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT uuid, name, type, last_seen, first_seen FROM players")
    raw_players = c.fetchall()
    conn.close()
    
    today = datetime.now(timezone.utc).date()
    players = []
    
    for uuid_val, name, p_type, last_seen, first_seen in raw_players:
        last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
        days_offline = (today - last_seen_date).days
        
        players.append({
            "uuid": uuid_val,
            "name": name,
            "type": p_type,
            "days_offline": days_offline,
            "last_seen": last_seen,
            "first_seen": first_seen
        })
    
    # Sortiere nach Tagen offline (aufsteigend) - aktivste zuerst
    players_sorted = sorted(players, key=lambda x: x["days_offline"])
    top_10 = players_sorted[:10]
    
    return render_template("top10.html", players=top_10)


@app.route("/trends")
@login_required
def trends():
    weekly_data = get_weekly_trends()
    
    stats = {
        "total_today": weekly_data[-1]["total"] if weekly_data else 0,
        "active_today": weekly_data[-1]["active"] if weekly_data else 0,
        "inactive_today": weekly_data[-1]["inactive"] if weekly_data else 0,
    }
    
    return render_template("trends.html", weekly_data=weekly_data, stats=stats)


@app.route("/activity-patterns")
@login_required
def activity_patterns():
    """Zeigt die Aktivitätsmuster nach Wochentag"""
    patterns = get_player_activity_patterns()
    
    # Berechne Statistiken
    total_activities = sum(p["count"] for p in patterns)
    max_count = max(p["count"] for p in patterns) if patterns else 1
    
    return render_template("activity_patterns.html", patterns=patterns, total=total_activities, max_count=max_count)


@app.route("/api/theme", methods=["POST"])
@login_required
def api_set_theme():
    """API für Theme-Umschaltung"""
    theme = request.json.get("theme", "dark")
    if theme not in ["dark", "light"]:
        theme = "dark"
    save_user_theme(current_user.id, theme)
    return jsonify({"success": True, "theme": theme})


@app.route("/api/toggle-widget", methods=["POST"])
@login_required
def api_toggle_widget():
    """API zum Ein/Ausschalten von Dashboard-Widgets"""
    widget_name = request.json.get("widget")
    enabled = request.json.get("enabled", True)
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE dashboard_widgets 
    SET enabled = ? 
    WHERE user_id = ? AND widget_name = ?
    """, (1 if enabled else 0, current_user.id, widget_name))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})


@app.route("/api/smart_search")
@login_required
def smart_search_api():
    """Smart Search API mit Filtern nach Name, Status, Version, Tagen offline"""
    query = request.args.get("q", "").lower()
    status_filter = request.args.get("status", "")  # aktiv, warnung, kritisch
    version_filter = request.args.get("version", "")  # java, bedrock
    min_days = request.args.get("min_days", type=int)
    max_days = request.args.get("max_days", type=int)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT uuid, name, type, last_seen FROM players")
    raw_players = c.fetchall()
    conn.close()
    
    today = datetime.now(timezone.utc).date()
    results = []
    
    for uuid_val, name, p_type, last_seen in raw_players:
        last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
        days_offline = (today - last_seen_date).days
        
        # Name filter
        if query and query not in name.lower():
            continue
        
        # Version filter
        if version_filter == "java" and p_type != "java":
            continue
        if version_filter == "bedrock" and p_type != "bedrock":
            continue
        
        # Status filter
        if status_filter == "aktiv" and days_offline > 7:
            continue
        if status_filter == "warnung" and not (7 < days_offline <= 21):
            continue
        if status_filter == "kritisch" and days_offline <= 21:
            continue
        
        # Days offline filter
        if min_days is not None and days_offline < min_days:
            continue
        if max_days is not None and days_offline > max_days:
            continue
        
        # Status bestimmen
        if days_offline <= 7:
            status = "aktiv"
        elif days_offline <= 21:
            status = "warnung"
        else:
            status = "kritisch"
        
        results.append({
            "uuid": uuid_val,
            "name": name,
            "type": p_type,
            "days_offline": days_offline,
            "status": status
        })
    
    return jsonify(results)


@app.route("/send_discord", methods=["POST"])
@login_required
def send_discord():
    filter_type = request.form.get("filter", "")
    version_filter = request.form.get("version", "")
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT uuid, name, type, last_seen FROM players")
    raw_players = c.fetchall()
    conn.close()
    
    today = datetime.now(timezone.utc).date()
    players = []
    
    for uuid_val, name, p_type, last_seen in raw_players:
        last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
        days_offline = (today - last_seen_date).days
        
        if version_filter == "java" and p_type != "java":
            continue
        if version_filter == "bedrock" and p_type != "bedrock":
            continue
        
        if filter_type == "aktiv" and days_offline > 7:
            continue
        if filter_type == "warnung" and not (7 < days_offline < 21):
            continue
        if filter_type == "kritisch" and days_offline < 21:
            continue
        
        players.append({
            "name": name,
            "type": p_type,
            "days_offline": days_offline,
            "last_seen": last_seen
        })
    
    # Sende Discord Message in separatem Thread
    thread = threading.Thread(target=send_discord_embeds, args=(players,))
    thread.daemon = True
    thread.start()
    
    return jsonify({"success": True, "message": "Discord Nachricht wird gesendet..."})


@app.route("/api/search")
@login_required
def api_search():
    query = request.args.get("q", "").lower()
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT uuid, name, type, last_seen FROM players")
    raw_players = c.fetchall()
    conn.close()
    
    today = datetime.now(timezone.utc).date()
    results = []
    
    for uuid_val, name, p_type, last_seen in raw_players:
        if query and query not in name.lower():
            continue
        
        last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
        days_offline = (today - last_seen_date).days
        
        results.append({
            "name": name,
            "type": p_type,
            "days_offline": days_offline
        })
    
    return jsonify(results)


# ---------------- BACKGROUND SCHEDULER ----------------
def _trends_scheduler(interval_minutes=3):
    """Background loop that runs calculate_trends() every `interval_minutes` minutes."""
    while True:
        try:
            calculate_trends()
        except Exception:
            # Swallow exceptions to keep the scheduler alive; retries inside calculate_trends handle locks
            pass
        time.sleep(interval_minutes * 60)


def _db_monitor(check_interval_seconds=10):
    """Periodically check the DB for lock errors by doing a lightweight query.

    If a lock is detected, log it to `db_lock.log` and the application logger.
    """
    logger = logging.getLogger("db_monitor")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("db_lock.log")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(fh)

    while True:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            conn.close()
        except sqlite3.OperationalError as e:
            msg = str(e)
            if "database is locked" in msg:
                logger.error("Detected database is locked: %s", msg)
                print("[db_monitor] Detected database is locked:", msg)
        except Exception as e:
            # Log unexpected exceptions but keep monitoring
            logger.exception("Unexpected error in DB monitor: %s", e)
        time.sleep(check_interval_seconds)


def start_background_tasks():
    """Start background scheduler and monitor threads.

    This is invoked manually because Flask 3 removed before_first_request.
    """
    t = threading.Thread(target=_trends_scheduler, args=(3,))
    t.daemon = True
    t.start()
    # Start DB monitor thread
    monitor = threading.Thread(target=_db_monitor, args=(10,))
    monitor.daemon = True
    monitor.start()


import os

# Start background tasks when running under gunicorn or directly
start_background_tasks()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
