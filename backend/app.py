import os
import json
import base64
import time
import uuid
import psycopg2
import jwt
import bcrypt
import datetime
import enum
import tempfile
import werkzeug.utils
from functools import wraps
from psycopg2 import pool
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
from pydantic import BaseModel
from google import genai
from google.genai import types

load_dotenv()

app = Flask(__name__, static_folder='static')
# Limit uploads to 50 MB (Adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
CORS(app)
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000", "http://localhost:5173"])

client = genai.Client()
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set!")

# Ensure local upload directory exists to prevent Base64 database bloat
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create a pool of 1 to 20 connections
db_pool = pool.ThreadedConnectionPool(1, 20, DATABASE_URL)

# --- Database Setup & Auto-Healing ---
def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issues (
            id SERIAL PRIMARY KEY,
            category VARCHAR(100),
            severity VARCHAR(50),
            description TEXT,
            address TEXT,
            city VARCHAR(100),
            lat FLOAT,
            lng FLOAT,
            media_url TEXT,
            status VARCHAR(50) DEFAULT 'Under Review',
            upvotes INT DEFAULT 0,
            verified_by TEXT[] DEFAULT '{}', 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            reporter_id TEXT,
            contact_no VARCHAR(15),
            is_live BOOLEAN DEFAULT FALSE,
            satisfaction_rating INT DEFAULT NULL
        )
    ''')
    cursor.execute("ALTER TABLE issues ADD COLUMN IF NOT EXISTS is_live BOOLEAN DEFAULT FALSE;")
    cursor.execute("ALTER TABLE issues ADD COLUMN IF NOT EXISTS satisfaction_rating INT DEFAULT NULL;")
    cursor.execute("ALTER TABLE issues ADD COLUMN IF NOT EXISTS assigned_admin VARCHAR(50);")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            assigned_city VARCHAR(100) NOT NULL,
            role VARCHAR(50) DEFAULT 'local_admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_login_history (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50),
            ip_address VARCHAR(50),
            location VARCHAR(100) DEFAULT 'Unknown',
            device_info TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logout_time TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS citizens (
            contact_no VARCHAR(15) PRIMARY KEY,
            password_hash VARCHAR(255),
            name VARCHAR(100),
            address TEXT,
            language VARCHAR(10) DEFAULT 'en',
            xp INT DEFAULT 0,
            rank VARCHAR(50) DEFAULT 'Observer',
            is_blocked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("ALTER TABLE citizens ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);")
    cursor.execute("ALTER TABLE citizens ADD COLUMN IF NOT EXISTS language VARCHAR(10) DEFAULT 'en';")
    cursor.execute("ALTER TABLE citizens ADD COLUMN IF NOT EXISTS username VARCHAR(50);")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_badges (
            contact_no VARCHAR(15),
            badge_name VARCHAR(100),
            PRIMARY KEY (contact_no, badge_name)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            contact_no VARCHAR(15),
            username VARCHAR(50),
            title VARCHAR(100),
            message TEXT,
            type VARCHAR(50),
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("ALTER TABLE notifications ADD COLUMN IF NOT EXISTS username VARCHAR(50);")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_bugs (
            id SERIAL PRIMARY KEY,
            reporter_id VARCHAR(50),
            reporter_role VARCHAR(20),
            description TEXT,
            status VARCHAR(50) DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Add these indexes to speed up filtering and location sorting
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_city ON issues(city);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_lat_lng ON issues(lat, lng);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_created_at ON issues(created_at);")

    conn.commit(); cursor.close(); conn.close()

init_db()

# --- Advanced Security Auth Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token_header = request.headers.get('Authorization')
        if not token_header or not token_header.startswith("Bearer "): 
            return jsonify({'error': 'Token is missing or malformed!'}), 401
        try:
            token = token_header.split(" ")[1] 
            current_user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            # SESSION INVALIDATION CHECK
            session_id = current_user.get('session_id')
            if session_id:
                conn = None
                try:
                    conn = db_pool.getconn()
                    cursor = conn.cursor()
                    cursor.execute("SELECT logout_time FROM admin_login_history WHERE id = %s", (session_id,))
                    row = cursor.fetchone()
                    cursor.close()
                    if row and row[0] is not None:
                        return jsonify({'error': 'Session terminated. Your account was accessed from another device.'}), 401
                except Exception as e:
                    if conn: conn.rollback()
                finally:
                    if conn is not None:
                        db_pool.putconn(conn)
        except Exception:
            return jsonify({'error': 'Token is invalid or expired!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def citizen_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token_header = request.headers.get('Authorization')
        if not token_header or not token_header.startswith("Bearer "): 
            return jsonify({'error': 'Token is missing or malformed!'}), 401
        try:
            token = token_header.split(" ")[1] 
            current_user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if 'contact_no' not in current_user:
                return jsonify({'error': 'Invalid citizen token!'}), 401
        except Exception:
            return jsonify({'error': 'Token is invalid or expired!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Helpers ---
RANKS = [
    {"name": "Observer", "min_xp": 0}, {"name": "Scout", "min_xp": 100},
    {"name": "Operative", "min_xp": 500}, {"name": "Vanguard", "min_xp": 1000}, {"name": "Legend", "min_xp": 2500}
]

def send_notification(cursor, contact_no=None, username=None, title="", message="", notif_type=""):
    cursor.execute("INSERT INTO notifications (contact_no, username, title, message, type) VALUES (%s, %s, %s, %s, %s)", 
                   (contact_no, username, title, message, notif_type))
    if contact_no: socketio.emit('new_notification', {"contact_no": contact_no})
    if username: socketio.emit('admin_notification', {"username": username})

def notify_city_admins(cursor, city, cat, sev, desc):
    # Check if the city has any assigned local admins
    cursor.execute("SELECT username FROM admins WHERE assigned_city = %s AND role = 'local_admin'", (city,))
    local_admins = cursor.fetchall()
    
    # Get all super admins
    cursor.execute("SELECT username FROM admins WHERE role = 'super_admin'")
    super_admins = cursor.fetchall()
    
    if local_admins:
        title = "New Regional Alert"
        message = f"A {sev} severity {cat} was reported in {city}."
        for admin in local_admins:
            send_notification(cursor, username=admin[0], title=title, message=message, notif_type="SYSTEM")
        for sa in super_admins:
            send_notification(cursor, username=sa[0], title=title, message=message, notif_type="SYSTEM")
    else:
        # UNMANAGED CITY OVERRIDE: Send specialized notification ONLY to Super Admins
        title = "⚠️ Unmanaged City Alert"
        message = f"An issue has been reported from {city}, which currently has NO local admin. Details: {sev} severity {cat} - {desc}"
        for sa in super_admins:
            send_notification(cursor, username=sa[0], title=title, message=message, notif_type="SYSTEM")

def award_xp(cursor, contact_no, amount, reason):
    # Fixed race condition: uses atomic UPDATE returning new XP
    cursor.execute("UPDATE citizens SET xp = xp + %s WHERE contact_no = %s RETURNING xp, rank", (amount, contact_no))
    row = cursor.fetchone()
    if not row: return
    new_xp, current_rank = row[0], row[1]
    
    new_rank = current_rank
    for r in reversed(RANKS):
        if new_xp >= r["min_xp"]:
            new_rank = r["name"]
            break
            
    if new_rank != current_rank:
        cursor.execute("UPDATE citizens SET rank = %s WHERE contact_no = %s", (new_rank, contact_no))
        send_notification(cursor, contact_no=contact_no, title="Rank Up!", message=f"You've been promoted to {new_rank}!", notif_type="RANK_UP")

def check_badges(cursor, contact_no):
    cursor.execute("SELECT badge_name FROM user_badges WHERE contact_no = %s", (contact_no,))
    earned = [r[0] for r in cursor.fetchall()]
    
    if "Tactical Spotter" not in earned:
        cursor.execute("SELECT COUNT(*) FROM issues WHERE contact_no = %s AND status = 'Resolved' AND severity = 'High'", (contact_no,))
        if cursor.fetchone()[0] >= 5:
            cursor.execute("INSERT INTO user_badges (contact_no, badge_name) VALUES (%s, 'Tactical Spotter')", (contact_no,))
            award_xp(cursor, contact_no, 250, "Tactical Spotter")
            send_notification(cursor, contact_no=contact_no, title="Badge Unlocked: Tactical Spotter", message="+250 XP!", notif_type="BADGE")

    if "Night Owl" not in earned:
        cursor.execute("SELECT COUNT(*) FROM issues WHERE contact_no = %s AND status = 'Resolved' AND is_live = TRUE AND EXTRACT(HOUR FROM created_at) < 4", (contact_no,))
        if cursor.fetchone()[0] >= 3:
            cursor.execute("INSERT INTO user_badges (contact_no, badge_name) VALUES (%s, 'Night Owl')", (contact_no,))
            award_xp(cursor, contact_no, 100, "Night Owl Badge")
            send_notification(cursor, contact_no=contact_no, title="Badge Unlocked: Night Owl", message="+100 XP!", notif_type="BADGE")

    if "Map Explorer" not in earned:
        cursor.execute("SELECT COUNT(DISTINCT city) FROM issues WHERE contact_no = %s AND status = 'Resolved'", (contact_no,))
        if cursor.fetchone()[0] >= 3:
            cursor.execute("INSERT INTO user_badges (contact_no, badge_name) VALUES (%s, 'Map Explorer')", (contact_no,))
            award_xp(cursor, contact_no, 300, "Map Explorer Badge")
            send_notification(cursor, contact_no=contact_no, title="Badge Unlocked: Map Explorer", message="+300 XP!", notif_type="BADGE")

    if "The Rizzler of Roads" not in earned:
        cursor.execute("SELECT COUNT(*) FROM issues WHERE contact_no = %s AND status = 'Resolved' AND category IN ('Pothole', 'General Road Hazard') AND LENGTH(description) > 50", (contact_no,))
        if cursor.fetchone()[0] >= 1:
            cursor.execute("INSERT INTO user_badges (contact_no, badge_name) VALUES (%s, 'The Rizzler of Roads')", (contact_no,))
            award_xp(cursor, contact_no, 150, "Rizzler Badge")
            send_notification(cursor, contact_no=contact_no, title="Badge Unlocked: Rizzler of Roads", message="+150 XP!", notif_type="BADGE")
            
    cursor.connection.commit()

SYSTEM_INSTRUCTION = """
You are the core AI backend for a hyperlocal community issue solver platform. Your job is to analyze images uploaded by citizens reporting local problems. 
Your rules:
1. Analyze the image to identify the type of issue. Use ONLY the categories provided.
2. Assess the severity based on public safety impact (Low, Medium, High).
3. Provide a brief, objective 1-sentence description of the issue.
4. Safety Check: If the image is unrelated to public infrastructure, looks like a prank, or is suspicious, flag `is_safe` to false (unsafe).
"""
class IssueCategory(str, enum.Enum):
    POTHOLE = "Pothole"
    WATER_LEAKAGE = "Water Leakage"
    STREETLIGHT = "Damaged Streetlight"
    WASTE = "Waste Management"
    ROAD_HAZARD = "General Road Hazard"
    OTHER = "Other"

class IssueReport(BaseModel):
    category: IssueCategory 
    severity: str
    description: str
    is_safe: bool

@socketio.on('join_city')
def handle_join_city(data):
    city = data.get('city')
    previous_city = data.get('previous_city')
    
    if previous_city:
        leave_room(previous_city)
        
    if city and city != 'Unknown':
        join_room(city)
        print(f"Client {request.sid} joined room: {city}")

# ==========================================
# CITIZEN IDENTITY & PROFILE
# ==========================================
@app.route('/api/citizen/check_username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    if not username: return jsonify({"available": False})
    
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM citizens WHERE username = %s", (username,))
        exists = cursor.fetchone()
        cursor.close()
        return jsonify({"available": not exists}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/citizen/register', methods=['POST'])
def register_citizen():
    data = request.json
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT contact_no FROM citizens WHERE contact_no = %s", (data['contact_no'],))
        if cursor.fetchone(): return jsonify({"error": "Account already exists. Please login."}), 400
        
        cursor.execute("SELECT 1 FROM citizens WHERE username = %s", (data.get('username'),))
        if cursor.fetchone(): return jsonify({"error": "Username already taken."}), 400
        
        hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        lang = data.get('language', 'en')
        
        cursor.execute("INSERT INTO citizens (contact_no, password_hash, name, address, language, username) VALUES (%s, %s, %s, %s, %s, %s)", 
                       (data['contact_no'], hashed, data['name'], data['address'], lang, data.get('username')))
        conn.commit(); cursor.close()
        token = jwt.encode({
            'contact_no': data['contact_no'], 
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET, algorithm="HS256")
        return jsonify({"message": "Profile created", "token" : token}), 201
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/citizen/login', methods=['POST'])
def login_citizen():
    data = request.json
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT name, is_blocked, password_hash, language FROM citizens WHERE contact_no = %s", (data['contact_no'],))
        user = cursor.fetchone()
        
        if not user: return jsonify({"error": "Account not found. Please register."}), 404
        if user[1]: return jsonify({"error": "This account is blocked."}), 403
        
        if user[2] is None:
            hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("UPDATE citizens SET password_hash = %s WHERE contact_no = %s", (hashed, data['contact_no']))
            conn.commit(); cursor.close()
            return jsonify({"message": "Legacy account secured.", "name": user[0], "language": user[3]}), 200

        if bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
            if 'language' in data and data['language'] != user[3]:
                cursor.execute("UPDATE citizens SET language = %s WHERE contact_no = %s", (data['language'], data['contact_no']))
                conn.commit()
                user_lang = data['language']
            else:
                user_lang = user[3]
            cursor.close()
            token = jwt.encode({
                'contact_no': data['contact_no'], 
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }, JWT_SECRET, algorithm="HS256")
            
            return jsonify({
                "message": "Login successful", 
                "token": token, 
                "name": user[0], 
                "language": user_lang
            }), 200
            
        cursor.close()
        return jsonify({"error": "Invalid password."}), 401
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/citizen/profile', methods=['GET', 'PUT'])
@citizen_token_required
def handle_citizen_profile(current_user):
    contact_no = current_user['contact_no']
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if request.method == 'GET':
            cursor.execute("SELECT name, address, xp, rank, language, username FROM citizens WHERE contact_no = %s", (contact_no,))
            user = cursor.fetchone()
            if not user: return jsonify({"error": "Not found"}), 404
            
            cursor.execute("SELECT COUNT(*) FROM issues WHERE contact_no = %s AND DATE(created_at) = CURRENT_DATE", (contact_no,))
            reports_today = cursor.fetchone()[0]
            cursor.execute("SELECT badge_name FROM user_badges WHERE contact_no = %s", (contact_no,))
            badges = [r[0] for r in cursor.fetchall()]
            cursor.execute("SELECT COUNT(*) FROM notifications WHERE contact_no = %s AND is_read = FALSE", (contact_no,))
            unread_notifs = cursor.fetchone()[0]
            cursor.close()
            return jsonify({"name": user[0], "address": user[1], "xp": user[2], "rank": user[3], "language": user[4], "username": user[5], "reports_today": reports_today, "reports_limit": 5, "badges": badges, "unread_notifications": unread_notifs}), 200

        if request.method == 'PUT':
            data = request.json
            cursor.execute("UPDATE citizens SET name = %s, address = %s, language = %s WHERE contact_no = %s", (data['name'], data['address'], data.get('language', 'en'), contact_no))
            conn.commit(); cursor.close()
            return jsonify({"message": "Profile updated"}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/notifications', methods=['GET', 'POST'])
def handle_all_notifications():
    # Securely extract identity from header instead of payload
    token_header = request.headers.get('Authorization')
    if not token_header or not token_header.startswith("Bearer "):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        token = token_header.split(" ")[1]
        current_user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        is_admin = 'role' in current_user
        contact_no = current_user.get('contact_no')
        username = current_user.get('username')
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401

    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if request.method == 'GET':
            if not is_admin and contact_no: 
                cursor.execute("SELECT id, title, message, type, created_at, is_read FROM notifications WHERE contact_no = %s ORDER BY created_at DESC LIMIT 20", (contact_no,))
            elif is_admin and username: 
                cursor.execute("SELECT id, title, message, type, created_at, is_read FROM notifications WHERE username = %s ORDER BY created_at DESC LIMIT 20", (username,))
            notifs = [{"id": r[0], "title": r[1], "message": r[2], "type": r[3], "created_at": r[4].isoformat(), "is_read": r[5]} for r in cursor.fetchall()]
            cursor.close()
            return jsonify({"notifications": notifs}), 200
            
        if request.method == 'POST':
            if not is_admin and contact_no: 
                cursor.execute("UPDATE notifications SET is_read = TRUE WHERE contact_no = %s", (contact_no,))
            elif is_admin and username: 
                cursor.execute("UPDATE notifications SET is_read = TRUE WHERE username = %s", (username,))
            conn.commit(); cursor.close()
            return jsonify({"message": "Marked read"}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

# ==========================================
# REPORTING & BUGS
# ==========================================
@app.route('/api/analyze', methods=['POST'])
def analyze_issue():
    if 'media' not in request.files: 
        return jsonify({"error": "No media"}), 400
        
    try:
        file = request.files['media']

        # 1. Save and let the 'with' block close the file securely
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.split('.')[-1]}") as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name

        # 2. UN-INDENTED: Upload to Gemini only after the file lock is released
        uploaded_file = client.files.upload(file=temp_path)

        res = client.models.generate_content(
            model='gemini-3.6-flash', 
            contents=["Analyze issue.", uploaded_file], 
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION, 
                response_mime_type="application/json", 
                response_schema=IssueReport, 
                temperature=0.2
            )
        )
        data = json.loads(res.text)

        # Clean up temp file and Gemini cloud file
        os.remove(temp_path)
        client.files.delete(name=uploaded_file.name)
        
        if not data.get('is_safe'): 
            return jsonify({"error": "Irrelevant content."}), 403
            
        return jsonify({"data": data}), 200
    except Exception as e:
        print(f"AI Analysis Error: {e}") # Log internally
        return jsonify({"error": "Failed to analyze media."}), 500

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webm', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/report', methods=['POST'])
@citizen_token_required
def report_issue(current_user):
    contact_no = current_user['contact_no']
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT is_blocked FROM citizens WHERE contact_no = %s", (contact_no,))
        user = cursor.fetchone()
        if not user or user[0]: return jsonify({"error": "Account blocked."}), 403
        
        cursor.execute("SELECT COUNT(*) FROM issues WHERE contact_no = %s AND DATE(created_at) = CURRENT_DATE", (contact_no,))
        if cursor.fetchone()[0] >= 5: return jsonify({"error": "Daily limit reached."}), 429

        # Security fix: Save raw file to disk instead of polluting DB with Base64
        file = request.files.get('media')
        if not file or not allowed_file(file.filename):
            if conn: conn.rollback()
            return jsonify({"error": "Invalid or missing media file."}), 400
        safe_filename = werkzeug.utils.secure_filename(file.filename) or "media.bin"
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        
        media_url = f"{request.host_url}static/uploads/{unique_filename}"
        
        cat, sev, desc, addr, city, lat, lng, is_live = request.form.get('category'), request.form.get('severity'), request.form.get('description'), request.form.get('address'), request.form.get('city', 'Unknown'), request.form.get('lat'), request.form.get('lng'), request.form.get('is_live') == 'true'
        
        cursor.execute("INSERT INTO issues (category, severity, description, address, city, lat, lng, media_url, contact_no, is_live) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id, created_at", (cat, sev, desc, addr, city, lat, lng, media_url, contact_no, is_live))
        issue_id, created_at = cursor.fetchone()
        
        award_xp(cursor, contact_no, 10, "Report Submitted")
        notify_city_admins(cursor, city, cat, sev, desc)
        conn.commit(); cursor.close()
        
        # Removed "reporter_id": contact_no from the public broadcast payload
        socketio.emit('new_issue', {
            "id": issue_id, "category": cat, "severity": sev, 
            "description": desc, "address": addr, "city": city, 
            "media_url": media_url, "status": "Under Review", 
            "upvotes": 0, "has_voted": False, "created_at": created_at.isoformat()
        }, room=city)
        return jsonify({"message": "Reported!", "issue_id": issue_id}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/issues/nearby', methods=['GET'])
def get_nearby_issues():
    lat, lng, contact_no, city = request.args.get('lat', type=float), request.args.get('lng', type=float), request.args.get('contact_no'), request.args.get('city')
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if city and city != 'Unknown':
            if lat and lng: cursor.execute("SELECT id, category, severity, description, address, media_url, status, upvotes, created_at, verified_by, contact_no, satisfaction_rating FROM issues WHERE status NOT IN ('Rejected') AND city = %s AND lat IS NOT NULL AND lng IS NOT NULL ORDER BY (POWER(lat - %s, 2) + POWER(lng - %s, 2)) ASC LIMIT 100", (city, lat, lng))
            else: cursor.execute("SELECT id, category, severity, description, address, media_url, status, upvotes, created_at, verified_by, contact_no, satisfaction_rating FROM issues WHERE status NOT IN ('Rejected') AND city = %s ORDER BY created_at DESC LIMIT 100", (city,))
        else:
            if lat and lng: cursor.execute("SELECT id, category, severity, description, address, media_url, status, upvotes, created_at, verified_by, contact_no, satisfaction_rating FROM issues WHERE status NOT IN ('Rejected') AND lat IS NOT NULL AND lng IS NOT NULL ORDER BY (POWER(lat - %s, 2) + POWER(lng - %s, 2)) ASC LIMIT 100", (lat, lng))
            else: cursor.execute("SELECT id, category, severity, description, address, media_url, status, upvotes, created_at, verified_by, contact_no, satisfaction_rating FROM issues WHERE status NOT IN ('Rejected') ORDER BY created_at DESC LIMIT 100")
        
        issues = [{
            "id": r[0], "category": r[1], "severity": r[2], "description": r[3], 
            "address": r[4], "media_url": r[5], "status": r[6], "upvotes": r[7], 
            "created_at": r[8].isoformat() if r[8] else None, 
            "has_voted": contact_no in (r[9] or []) if contact_no else False, 
            "is_mine": r[10] == contact_no, # <-- SAFE BOOLEAN
            "satisfaction_rating": r[11]
        } for r in cursor.fetchall()]
        cursor.close()
        return jsonify({"issues": issues}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/issues/<int:issue_id>', methods=['GET'])
def get_single_issue(issue_id):
    contact_no = request.args.get('contact_no')
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        # FIX: Select all 12 required columns to match the dictionary mapping
        cursor.execute("""
            SELECT id, category, severity, description, address, 
                   media_url, status, upvotes, created_at, 
                   verified_by, contact_no, satisfaction_rating 
            FROM issues WHERE id = %s
        """, (issue_id,))
        
        r = cursor.fetchone()
        if not r: 
            cursor.close()
            return jsonify({"error": "Global Issue ID not found"}), 404
        
        # Update indices to match the new SQL selection
        verified_by, reporter_id = r[9] or [], r[10]
        
        issue = {
            "id": r[0], 
            "category": r[1], 
            "severity": r[2], 
            "description": r[3], 
            "address": r[4], 
            "media_url": r[5], 
            "status": r[6], 
            "upvotes": r[7], 
            "created_at": r[8].isoformat() if r[8] else None, 
            "has_voted": contact_no in verified_by if contact_no else False, 
            "is_mine": reporter_id == contact_no, 
            "satisfaction_rating": r[11]
        }
        return jsonify({"issue": issue}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") 
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/citizen/my_issues', methods=['GET'])
@citizen_token_required
def get_my_issues(current_user):
    contact_no = current_user['contact_no']
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, category, status, created_at FROM issues WHERE contact_no = %s ORDER BY created_at DESC", (contact_no,))
        issues = [{"id": r[0], "category": r[1], "status": r[2], "date": r[3].strftime("%Y-%m-%d %H:%M")} for r in cursor.fetchall()]
        cursor.close()
        return jsonify({"issues": issues}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/issues/<int:issue_id>/verify', methods=['POST'])
@citizen_token_required
def verify_issue(current_user, issue_id):
    contact_no = current_user['contact_no']
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT verified_by, contact_no FROM issues WHERE id = %s FOR UPDATE", (issue_id,))
        row = cursor.fetchone()
        
        verified_by, reporter_id = row[0] or [], row[1]
        if contact_no == reporter_id: 
            conn.rollback()
            return jsonify({"error": "Cannot verify own report."}), 400
            
        has_voted = False
        if contact_no in verified_by: verified_by.remove(contact_no)
        else: 
            verified_by.append(contact_no)
            has_voted = True
            award_xp(cursor, contact_no, 5, "Verified Issue") 
            
        new_upvotes = len(verified_by)
        cursor.execute("UPDATE issues SET verified_by = %s, upvotes = %s WHERE id = %s", (verified_by, new_upvotes, issue_id))
        conn.commit(); cursor.close()
        return jsonify({"upvotes": new_upvotes, "has_voted": has_voted}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/issues/<int:issue_id>/rate', methods=['POST'])
@citizen_token_required
def rate_issue(current_user, issue_id):
    contact_no = current_user['contact_no']
    data = request.json
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("UPDATE issues SET satisfaction_rating = %s WHERE id = %s AND contact_no = %s", 
                       (data['rating'], issue_id, contact_no))
        conn.commit(); cursor.close()
        return jsonify({"message": "Rated"}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/bugs', methods=['GET', 'POST'])
def handle_bugs():
    # --- NEW: Secure Token Verification ---
    token_header = request.headers.get('Authorization')
    if not token_header or not token_header.startswith("Bearer "):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        token = token_header.split(" ")[1]
        current_user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        role_from_token = current_user.get('role', 'citizen')
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401
    # --------------------------------------

    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        if request.method == 'POST':
            data = request.json
            # Enforce the role from the token, ignoring any spoofed client payload
            cursor.execute("INSERT INTO app_bugs (reporter_id, reporter_role, description) VALUES (%s, %s, %s)", 
                           (data['reporter_id'], role_from_token, data['description']))
            conn.commit(); cursor.close()
            return jsonify({"message": "Reported successfully."}), 201
            
        if request.method == 'GET':
            # Enforce role from token, ignoring the ?role= URL parameter
            if role_from_token == 'super_admin':
                cursor.execute("SELECT id, reporter_id, reporter_role, description, status, created_at FROM app_bugs WHERE reporter_role IN ('local_admin', 'super_admin') ORDER BY created_at DESC")
            else:
                cursor.execute("SELECT id, reporter_id, reporter_role, description, status, created_at FROM app_bugs WHERE reporter_role = 'citizen' ORDER BY created_at DESC")
            
            bugs = [{"id": r[0], "reporter_id": r[1], "reporter_role": r[2], "description": r[3], "status": r[4], "created_at": r[5].isoformat()} for r in cursor.fetchall()]
            cursor.close()
            return jsonify({"bugs": bugs}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/bugs/<int:bug_id>/escalate', methods=['POST'])
@token_required
def escalate_bug(current_user, bug_id):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("UPDATE app_bugs SET reporter_role = 'local_admin', status = 'Escalated' WHERE id = %s", (bug_id,))
        conn.commit(); cursor.close()
        return jsonify({"message": "Problem escalated."}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

# ==========================================
# SUPER ADMIN
# ==========================================
@app.route('/api/admin/users', methods=['GET', 'POST'])
@token_required
def handle_users(current_user):
    if current_user['role'] != 'super_admin': return jsonify({"error": "Unauthorized"}), 403
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if request.method == 'GET':
            cursor.execute("SELECT id, username, assigned_city, role, created_at FROM admins ORDER BY created_at DESC")
            admins = [{"id": r[0], "username": r[1], "assigned_city": r[2], "role": r[3], "created_at": r[4].isoformat() if r[4] else None} for r in cursor.fetchall()]
            cursor.close()
            return jsonify({"admins": admins}), 200
            
        if request.method == 'POST':
            data = request.json
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(data['password'].encode('utf-8'), salt).decode('utf-8')
            cursor.execute("INSERT INTO admins (username, password_hash, assigned_city, role) VALUES (%s, %s, %s, %s)",
                (data['username'], hashed, data['assigned_city'], data['role']))
            conn.commit(); cursor.close()
            return jsonify({"message": "Admin created successfully!"}), 201
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/users/<int:admin_id>', methods=['PUT', 'DELETE'])
@token_required
def update_delete_user(current_user, admin_id):
    if current_user['role'] != 'super_admin': return jsonify({"error": "Unauthorized"}), 403
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if request.method == 'PUT':
            data = request.json
            if data.get('password'):
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(data['password'].encode('utf-8'), salt).decode('utf-8')
                cursor.execute("UPDATE admins SET username=%s, assigned_city=%s, role=%s, password_hash=%s WHERE id=%s",
                    (data['username'], data['assigned_city'], data['role'], hashed, admin_id))
            else:
                cursor.execute("UPDATE admins SET username=%s, assigned_city=%s, role=%s WHERE id=%s",
                    (data['username'], data['assigned_city'], data['role'], admin_id))
            conn.commit(); cursor.close()
            return jsonify({"message": "Admin updated successfully!"}), 200
            
        if request.method == 'DELETE':
            cursor.execute("DELETE FROM admins WHERE id = %s", (admin_id,))
            conn.commit(); cursor.close()
            return jsonify({"message": "Admin deleted!"}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

# ==========================================
# ADMIN AUTH & PERFORMANCE ROUTES
# ==========================================
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    ip_addr = request.remote_addr
    device_info = request.headers.get('User-Agent', 'Unknown Device')
    location = data.get('location', 'Unknown')
    force_login = data.get('force_login', False)
    
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, assigned_city, role, username FROM admins WHERE username = %s", (data.get('username'),))
        admin = cursor.fetchone()
        
        if admin and bcrypt.checkpw(data.get('password').encode('utf-8'), admin[1].encode('utf-8')):
            username = admin[4]
            
            # Active Session Check
            cursor.execute("SELECT id FROM admin_login_history WHERE username = %s AND logout_time IS NULL", (username,))
            active_sessions = cursor.fetchall()
            
            if active_sessions and not force_login:
                cursor.close()
                return jsonify({"error": "Active session exists on another device.", "requires_force": True}), 409
                
            if active_sessions and force_login:
                cursor.execute("UPDATE admin_login_history SET logout_time = CURRENT_TIMESTAMP WHERE username = %s AND logout_time IS NULL", (username,))
                
            # New Session Security Log
            cursor.execute("SELECT COUNT(*) FROM admin_login_history WHERE username = %s AND ip_address = %s", (username, ip_addr))
            is_new_device = cursor.fetchone()[0] == 0
            if is_new_device:
                send_notification(cursor, username=username, title="New Login Detected", message=f"Login from new IP: {ip_addr}", notif_type="SECURITY")
                
            cursor.execute("INSERT INTO admin_login_history (username, ip_address, device_info, location) VALUES (%s, %s, %s, %s) RETURNING id", (username, ip_addr, device_info, location))
            session_id = cursor.fetchone()[0]
            conn.commit()
            
            token = jwt.encode({'admin_id': admin[0], 'username': username, 'assigned_city': admin[2], 'role': admin[3], 'session_id': session_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)}, JWT_SECRET, algorithm="HS256")
            cursor.close()
            return jsonify({"message": "Login successful", "token": token, "city": admin[2], "role": admin[3], "username": username}), 200
        
        cursor.close()
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/logout', methods=['POST'])
@token_required
def admin_logout(current_user):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        session_id = current_user.get('session_id')
        
        if session_id:
            cursor.execute("UPDATE admin_login_history SET logout_time = CURRENT_TIMESTAMP WHERE id = %s", (session_id,))
        else:
            cursor.execute("""
                UPDATE admin_login_history 
                SET logout_time = CURRENT_TIMESTAMP 
                WHERE username = %s AND logout_time IS NULL 
            """, (current_user['username'],))
            
        conn.commit(); cursor.close()
        return jsonify({"message": "Logged out"}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/verify_session', methods=['GET'])
@token_required
def verify_session(current_user):
    # If the token_required decorator passes, the session is valid
    return jsonify({"valid": True, "role": current_user['role']}), 200

@app.route('/api/admin/issues', methods=['GET'])
@token_required
def get_admin_issues(current_user):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        base_query = "SELECT i.id, i.category, i.severity, i.description, i.address, i.city, i.status, i.media_url, i.upvotes, c.name, i.contact_no, i.is_live, i.assigned_admin FROM issues i LEFT JOIN citizens c ON i.contact_no = c.contact_no"
        
        if current_user['role'] == 'super_admin': 
            cursor.execute(base_query + " ORDER BY i.created_at DESC")
        else: 
            cursor.execute(base_query + " WHERE (i.city = %s AND i.assigned_admin IS NULL) OR i.assigned_admin = %s ORDER BY CASE i.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, i.created_at DESC", (current_user['assigned_city'], current_user['username']))
            
        issues = [{"id": r[0], "category": r[1], "severity": r[2], "description": r[3], "address": r[4], "city": r[5], "status": r[6], "media_url": r[7], "upvotes": r[8], "reporter_name": r[9], "reporter_contact": r[10], "is_live": r[11], "assigned_admin": r[12]} for r in cursor.fetchall()]
        cursor.close()
        return jsonify({"issues": issues}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") 
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/issues/<int:issue_id>/assign', methods=['POST'])
@token_required
def assign_admin_to_issue(current_user, issue_id):
    if current_user['role'] != 'super_admin':
        return jsonify({"error": "Unauthorized. Only Super Admins can manually route issues."}), 403
        
    data = request.json
    assigned_admin = data.get('assigned_admin')
    
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if assigned_admin:
            cursor.execute("SELECT 1 FROM admins WHERE username = %s", (assigned_admin,))
            if not cursor.fetchone():
                return jsonify({"error": "Target admin not found."}), 404
                
        cursor.execute("UPDATE issues SET assigned_admin = %s WHERE id = %s", (assigned_admin, issue_id))
        conn.commit()
        cursor.close()
        return jsonify({"message": "Issue successfully routed."}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") 
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/status', methods=['POST'])
@token_required
def update_status(current_user):
    data = request.json
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT city FROM issues WHERE id = %s", (data['issue_id'],))
        issue_city_row = cursor.fetchone()
        issue_city = issue_city_row[0] if issue_city_row else None
        
        # 2. Check authorization for local admins
        if current_user['role'] != 'super_admin':
            if not issue_city or issue_city != current_user['assigned_city']:
                return jsonify({"error": "Unauthorized to modify issues outside your assigned city."}), 403
        
        if data['status'] == 'Resolved':
            cursor.execute("UPDATE issues SET status = %s, resolved_at = CURRENT_TIMESTAMP WHERE id = %s RETURNING contact_no", (data['status'], data['issue_id']))
            reporter = cursor.fetchone()
            if reporter:
                award_xp(cursor, reporter[0], 50, "Issue Resolved")
                send_notification(cursor, contact_no=reporter[0], title="Issue Resolved!", message=f"Your report #{data['issue_id']} was resolved. Please rate your satisfaction.", notif_type="STATUS")
                check_badges(cursor, reporter[0])
        else:

            if data['status'] == 'Rejected':
                cursor.execute("SELECT media_url FROM issues WHERE id = %s", (data['issue_id'],))
                row = cursor.fetchone()
                if row and row[0]:
                    # Extract filename from URL and delete it from the server
                    filename = row[0].split('/')[-1]
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    if os.path.exists(filepath):
                        os.remove(filepath)

            cursor.execute("UPDATE issues SET status = %s WHERE id = %s RETURNING contact_no", (data['status'], data['issue_id']))
            reporter = cursor.fetchone()
            if reporter: send_notification(cursor, contact_no=reporter[0], title="Status Update", message=f"Report #{data['issue_id']} is now {data['status']}.", notif_type="STATUS")
            
        conn.commit(); cursor.close()
        socketio.emit('status_update', {'issue_id': data['issue_id'], 'status': data['status']},room=issue_city)
        return jsonify({"message": "Updated"}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/performance', methods=['GET'])
@token_required
def admin_performance(current_user):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        city = current_user['assigned_city']
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_assigned,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as total_solved,
                COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0) as avg_res_time_seconds,
                COALESCE(AVG(satisfaction_rating), 0) as avg_csat 
            FROM issues 
            WHERE city = %s AND DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)
        """, (city,))
        row = cursor.fetchone()
        
        avg_seconds = int(row[2] or 0)
        hours, remainder = divmod(avg_seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        avg_time_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
        if avg_seconds == 0: avg_time_str = "N/A"

        metrics = {
            "monthly_assigned": int(row[0] or 0),
            "monthly_solved": int(row[1] or 0),
            "average_resolution_time": avg_time_str,
            "citizen_satisfaction": round(float(row[3] or 0), 1) if row[3] else "N/A"
        }
        cursor.close()
        return jsonify(metrics), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/superadmin/admins_stats', methods=['GET'])
@token_required
def superadmin_admins_stats(current_user):
    if current_user['role'] != 'super_admin': return jsonify({"error": "Unauthorized"}), 403
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, assigned_city, role FROM admins WHERE role = 'local_admin'")
        admins = cursor.fetchall()
        
        stats = []
        for admin in admins:
            city = admin[2]
            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN status = 'Under Review' THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as progress,
                    SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as solved,
                    COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0) as avg_res_time,
                    COALESCE(AVG(satisfaction_rating), 0) as avg_csat,
                    COUNT(*) as monthly_assigned,
                    SUM(CASE WHEN status = 'Resolved' AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) THEN 1 ELSE 0 END) as monthly_solved
                FROM issues 
                WHERE city = %s AND DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)
            """, (city,))
            row = cursor.fetchone()
            
            avg_seconds = int(row[3] or 0)
            hours, remainder = divmod(avg_seconds, 3600)
            avg_time_str = f"{hours}h {remainder//60}m" if hours > 0 else f"{remainder//60}m"
            if avg_seconds == 0: avg_time_str = "N/A"
            
            stats.append({
                "id": admin[0], "username": admin[1], "city": city,
                "active": int(row[0] or 0), "progress": int(row[1] or 0), "solved": int(row[2] or 0),
                "monthly_assigned": int(row[5] or 0), "monthly_solved": int(row[6] or 0),
                "avg_resolution_time": avg_time_str, "avg_csat": round(float(row[4] or 0), 1) if row[4] else "N/A"
            })
            
        cursor.close()
        return jsonify({"stats": stats}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/profile_data', methods=['GET'])
@token_required
def admin_profile_data(current_user):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        username = current_user['username']
        
        cursor.execute("SELECT ip_address, location, login_time, logout_time, device_info FROM admin_login_history WHERE username = %s ORDER BY login_time DESC LIMIT 10", (username,))
        login_history = []
        for r in cursor.fetchall():
            session_time = "Active"
            if r[3]:
                delta = r[3] - r[2]
                session_time = f"{delta.total_seconds() // 60:.0f} mins"
            
            device_str = r[4] or "Unknown Device"
            login_history.append({ 
                "ip": r[0], 
                "location": r[1] or 'Unknown', 
                "time": r[2].strftime("%Y-%m-%d %H:%M"), 
                "session": session_time, 
                "device": device_str 
            })
            
        cursor.execute("SELECT id, category, status, resolved_at FROM issues WHERE city = %s AND status != 'Under Review' ORDER BY COALESCE(resolved_at, created_at) DESC LIMIT 10", (current_user['assigned_city'],))
        activity_history = [{"id": r[0], "category": r[1], "status": r[2], "date": (r[3] or datetime.datetime.now()).strftime("%Y-%m-%d")} for r in cursor.fetchall()]
        
        cursor.close()
        return jsonify({"login_history": login_history, "activity_history": activity_history}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/block', methods=['POST'])
@token_required
def block_citizen(current_user):
    data = request.json
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("UPDATE citizens SET is_blocked = %s WHERE contact_no = %s", (data['is_blocked'], data['contact_no']))
        conn.commit(); cursor.close()
        return jsonify({"message": "User block status updated."}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/public/analytics', methods=['GET'])
def get_public_analytics():
    city = request.args.get('city')
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        if city and city != 'Unknown' and city != 'Global':
            cursor.execute("SELECT category, COUNT(*) FROM issues WHERE city = %s GROUP BY category", (city,))
            category_data = [{"name": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            cursor.execute("SELECT status, COUNT(*) FROM issues WHERE city = %s GROUP BY status", (city,))
            status_data = [{"name": row[0], "value": row[1]} for row in cursor.fetchall()]
            
            cursor.execute("SELECT lat, lng, status, category, severity FROM issues WHERE lat IS NOT NULL AND lng IS NOT NULL AND city = %s", (city,))
            map_data = [{"lat": row[0], "lng": row[1], "status": row[2], "category": row[3], "severity": row[4]} for row in cursor.fetchall()]
        else:
            cursor.execute("SELECT category, COUNT(*) FROM issues GROUP BY category")
            category_data = [{"name": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            cursor.execute("SELECT status, COUNT(*) FROM issues GROUP BY status")
            status_data = [{"name": row[0], "value": row[1]} for row in cursor.fetchall()]
            
            cursor.execute("SELECT lat, lng, status, category, severity FROM issues WHERE lat IS NOT NULL AND lng IS NOT NULL")
            map_data = [{"lat": row[0], "lng": row[1], "status": row[2], "category": row[3], "severity": row[4]} for row in cursor.fetchall()]
            
        cursor.close()
        return jsonify({"category_data": category_data, "status_data": status_data, "map_data": map_data}), 200
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database/Server Error: {str(e)}") # Ideally use the logging library here
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

@app.route('/api/admin/predict_issue/<int:issue_id>', methods=['GET'])
@token_required
def get_issue_insights(current_user, issue_id):
    conn = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT category, severity, description, address, city FROM issues WHERE id = %s", (issue_id,))
        issue = cursor.fetchone()
        cursor.close()
        if not issue: return jsonify({"error": "Issue not found"}), 404
        ai_prompt = f"Analyze reported issue:\nCategory: {issue[0]}\nSeverity: {issue[1]}\nDescription: {issue[2]}\nLocation: {issue[3]}\n\nProvide 3 quick bullet points:\n1. Potential root cause.\n2. Mitigation steps.\n3. Estimated repair complexity."
        response = client.models.generate_content(model='gemini-2.5-flash', contents=ai_prompt)
        return jsonify({"insights": response.text}), 200
    except Exception: 
        if conn: conn.rollback()
        return jsonify({"error": "AI Failed"}), 500
    finally:
        if conn is not None:
            db_pool.putconn(conn)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='127.0.0.1', port=port, debug=True)