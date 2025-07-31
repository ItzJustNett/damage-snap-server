
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import sqlite3
import os
import base64
import requests
import time
import json
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
import uvicorn
import jwt
from passlib.context import CryptContext
import hashlib

app = FastAPI(title="DamageSnap API", description="Wildfire Management & Recovery Database")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development. Restrict in production.
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
COLAB_AI_SERVER = "http://your-colab-url:5000"  # Update this!
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"

# Ensure uploads directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Mount static files
app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Pydantic models
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PostCreate(BaseModel):
    content: str
    location: Optional[str] = ""
    tags: Optional[List[str]] = []

class CommentCreate(BaseModel):
    content: str

class HelpRequestCreate(BaseModel):
    title: str
    location: str
    description: str
    fundingGoal: int
    category: str
    urgency: str

class DonationCreate(BaseModel):
    amount: float
    donorName: str
    email: str

class ChatMessage(BaseModel):
    content: str

class VolunteerEventCreate(BaseModel):
    title: str
    location: str
    description: str
    date: str
    startTime: str
    endTime: str
    maxVolunteers: int
    category: str
    difficulty: str

class VolunteerRequest(BaseModel):
    location_id: int
    user_id: str
    message: str = ""

class AnalysisResult(BaseModel):
    request_id: str
    result: Optional[dict] = None
    error: Optional[str] = None

class ServerURL(BaseModel):
    server_url: str

# ================ UTILITY FUNCTIONS ================

def format_time_ago(timestamp_str):
    """Format timestamp as time ago"""
    try:
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        now = datetime.utcnow()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600}h ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60}m ago"
        else:
            return "just now"
    except:
        return "unknown time"

def init_db():
    conn = sqlite3.connect('damagesnap.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        avatar_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Posts table
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        location TEXT,
        tags TEXT,
        likes INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Post likes table
    c.execute('''CREATE TABLE IF NOT EXISTS post_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(post_id, user_id)
    )''')
    
    # Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Help requests table
    c.execute('''CREATE TABLE IF NOT EXISTS help_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        location TEXT,
        description TEXT,
        funding_goal REAL,
        funding_raised REAL DEFAULT 0,
        category TEXT,
        urgency TEXT,
        supporters INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Donations table
    c.execute('''CREATE TABLE IF NOT EXISTS donations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        help_request_id INTEGER,
        donor_name TEXT,
        donor_email TEXT,
        amount REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(help_request_id) REFERENCES help_requests(id)
    )''')
    
    # Chat messages table
    c.execute('''CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Volunteer events table
    c.execute('''CREATE TABLE IF NOT EXISTS volunteer_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        location TEXT,
        description TEXT,
        event_date DATE,
        start_time TIME,
        end_time TIME,
        max_volunteers INTEGER,
        current_volunteers INTEGER DEFAULT 0,
        category TEXT,
        difficulty TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Event volunteers table
    c.execute('''CREATE TABLE IF NOT EXISTS event_volunteers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(event_id) REFERENCES volunteer_events(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(event_id, user_id)
    )''')
    
    # Damage reports table (existing)
    c.execute('''CREATE TABLE IF NOT EXISTS damage_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        latitude REAL,
        longitude REAL,
        photo_url TEXT,
        damage_score INTEGER,
        description TEXT,
        cost_estimate REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Recovery locations table (existing)
    c.execute('''CREATE TABLE IF NOT EXISTS recovery_locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        latitude REAL,
        longitude REAL,
        title TEXT,
        description TEXT,
        volunteers_needed INTEGER,
        photo_url TEXT,
        status TEXT DEFAULT 'active',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Volunteers table (existing)
    c.execute('''CREATE TABLE IF NOT EXISTS volunteers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        location_id INTEGER,
        user_id TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(location_id) REFERENCES recovery_locations(id)
    )''')
    
    # Analysis queue table (existing)
    c.execute('''CREATE TABLE IF NOT EXISTS analysis_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE,
        image_path TEXT,
        image_data TEXT,
        status TEXT DEFAULT 'pending',
        result TEXT,
        error_message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME
    )''')
    
    conn.commit()
    conn.close()

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def secure_filename(filename: str) -> str:
    return "".join(c for c in filename if c.isalnum() or c in (' ', '.', '_')).rstrip()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return int(user_id)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

def get_user_by_id(user_id: int):
    conn = sqlite3.connect('damagesnap.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

@app.get("/", response_class=HTMLResponse)
async def api_info():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DamageSnap API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
            h2 { color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
            .endpoint { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #3498db; }
            .method { background: #27ae60; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; margin-right: 10px; }
            .method.post { background: #e67e22; }
            .path { font-family: monospace; font-weight: bold; color: #2c3e50; }
            .description { color: #7f8c8d; margin-top: 5px; }
            .status { text-align: center; padding: 20px; background: #2ecc71; color: white; border-radius: 5px; margin-bottom: 30px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="status">
                <h1>🔥 DamageSnap FastAPI Server</h1>
                <p>Complete Wildfire Management & Recovery Platform</p>
            </div>
            
            <h2>📋 API Endpoints</h2>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/auth/register</span>
                <div class="description">👤 User registration</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/auth/login</span>
                <div class="description">🔐 User login</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/posts</span>
                <div class="description">📝 Create community post</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/community/leaderboard</span>
                <div class="description">🏆 Community leaderboard</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/help-requests</span>
                <div class="description">🆘 Create help request</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/donations</span>
                <div class="description">💰 Make donation</div>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/analyze-damage</span>
                <div class="description">🤖 AI-powered damage analysis</div>
            </div>
            
            <h2>🔗 Interactive Documentation</h2>
            <div style="background: #34495e; color: #ecf0f1; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0;">
                Visit <a href="/docs" style="color: #3498db;">/docs</a> for Swagger UI<br>
                Visit <a href="/redoc" style="color: #3498db;">/redoc</a> for ReDoc
            </div>
            
            <div style="text-align: center; margin-top: 30px; color: #7f8c8d;">
                <p>🤖 <strong>FastAPI Version:</strong> Complete platform with authentication, posts, donations, AI analysis, leaderboard</p>
                <p>🌲 Connecting communities for wildfire recovery and reforestation 🌲</p>
            </div>
        </div>
    </body>
    </html>
    '''

# ================ AUTHENTICATION ENDPOINTS ================

@app.post("/api/auth/register")
async def register_user(user: UserCreate):
    """Register a new user"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        # Check if user exists
        c.execute('SELECT id FROM users WHERE email = ?', (user.email,))
        if c.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password
        hashed_password = pwd_context.hash(user.password)
        
        # Create user
        c.execute('''INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)''',
                  (user.name, user.email, hashed_password))
        
        user_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Create token
        access_token = create_access_token({"sub": str(user_id)})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "name": user.name,
                "email": user.email
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/login")
async def login_user(user: UserLogin):
    """Login user"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM users WHERE email = ?', (user.email,))
        db_user = c.fetchone()
        conn.close()
        
        if not db_user or not pwd_context.verify(user.password, db_user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        access_token = create_access_token({"sub": str(db_user['id'])})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": db_user['id'],
                "name": db_user['name'],
                "email": db_user['email'],
                "avatar_url": db_user['avatar_url']
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/auth/me")
async def get_current_user(user_id: int = Depends(verify_token)):
    """Get current user info"""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    del user['password_hash']  # Don't return password hash
    return user

# ================ POSTS ENDPOINTS ================

@app.post("/api/posts")
async def create_post(post: PostCreate, user_id: int = Depends(verify_token)):
    """Create a new community post"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        tags_json = json.dumps(post.tags) if post.tags else "[]"
        
        c.execute('''INSERT INTO posts (user_id, content, location, tags)
                    VALUES (?, ?, ?, ?)''',
                  (user_id, post.content, post.location, tags_json))
        
        post_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {"id": post_id, "message": "Post created successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/posts")
async def get_posts(limit: int = Query(20), offset: int = Query(0)):
    """Get community posts"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT p.*, u.name as author_name, u.avatar_url,
                    (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
                    FROM posts p
                    JOIN users u ON p.user_id = u.id
                    ORDER BY p.created_at DESC
                    LIMIT ? OFFSET ?''',
                  (limit, offset))
        
        posts = []
        for row in c.fetchall():
            post = dict(row)
            post['tags'] = json.loads(post['tags']) if post['tags'] else []
            post['time'] = format_time_ago(post['created_at'])
            posts.append(post)
        
        conn.close()
        return posts
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/posts/{post_id}/like")
async def like_post(post_id: int, user_id: int = Depends(verify_token)):
    """Like/unlike a post"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        # Check if already liked
        c.execute('SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        existing_like = c.fetchone()
        
        if existing_like:
            # Unlike
            c.execute('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
            c.execute('UPDATE posts SET likes = likes - 1 WHERE id = ?', (post_id,))
            liked = False
        else:
            # Like
            c.execute('INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)', (post_id, user_id))
            c.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
            liked = True
        
        # Get updated like count
        c.execute('SELECT likes FROM posts WHERE id = ?', (post_id,))
        likes = c.fetchone()[0]
        
        conn.commit()
        conn.close()
        
        return {"liked": liked, "likes": likes}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/posts/{post_id}/comments")
async def add_comment(post_id: int, comment: CommentCreate, user_id: int = Depends(verify_token)):
    """Add comment to post"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO comments (post_id, user_id, content)
                    VALUES (?, ?, ?)''',
                  (post_id, user_id, comment.content))
        
        comment_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {"id": comment_id, "message": "Comment added"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/posts/{post_id}/comments")
async def get_comments(post_id: int):
    """Get comments for a post"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT c.*, u.name as author_name
                    FROM comments c
                    JOIN users u ON c.user_id = u.id
                    WHERE c.post_id = ?
                    ORDER BY c.created_at ASC''',
                  (post_id,))
        
        comments = []
        for row in c.fetchall():
            comment = dict(row)
            comment['time'] = format_time_ago(comment['created_at'])
            comments.append(comment)
        
        conn.close()
        return comments
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ COMMUNITY LEADERBOARD ENDPOINTS ================

@app.get("/api/community/leaderboard")
async def get_community_leaderboard(limit: int = Query(10)):
    """Get community leaderboard with user activity metrics"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Complex query to aggregate all user metrics
        c.execute('''
            SELECT 
                u.id,
                u.name,
                u.avatar_url,
                u.created_at as join_date,
                COALESCE(posts.count, 0) as posts_count,
                COALESCE(reports.count, 0) as damage_reports_count,
                COALESCE(events.count, 0) as events_joined_count,
                COALESCE(locations.count, 0) as recovery_locations_count,
                COALESCE(donations.total, 0) as total_donated,
                COALESCE(donations.count, 0) as donations_count,
                -- Calculate total activity score
                (COALESCE(posts.count, 0) * 2 + 
                 COALESCE(reports.count, 0) * 5 + 
                 COALESCE(events.count, 0) * 3 + 
                 COALESCE(locations.count, 0) * 10 + 
                 COALESCE(donations.count, 0) * 4) as activity_score
            FROM users u
            LEFT JOIN (
                SELECT user_id, COUNT(*) as count 
                FROM posts 
                GROUP BY user_id
            ) posts ON u.id = posts.user_id
            LEFT JOIN (
                SELECT user_id, COUNT(*) as count 
                FROM damage_reports 
                WHERE user_id IS NOT NULL
                GROUP BY user_id
            ) reports ON u.id = CAST(reports.user_id AS INTEGER)
            LEFT JOIN (
                SELECT user_id, COUNT(*) as count 
                FROM event_volunteers 
                GROUP BY user_id
            ) events ON u.id = events.user_id
            LEFT JOIN (
                SELECT user_id, COUNT(*) as count 
                FROM recovery_locations 
                WHERE user_id IS NOT NULL
                GROUP BY user_id
            ) locations ON u.id = CAST(locations.user_id AS INTEGER)
            LEFT JOIN (
                SELECT 
                    u2.id as user_id, 
                    SUM(d.amount) as total,
                    COUNT(*) as count
                FROM donations d
                JOIN users u2 ON d.donor_email = u2.email
                GROUP BY u2.id
            ) donations ON u.id = donations.user_id
            WHERE (COALESCE(posts.count, 0) + 
                   COALESCE(reports.count, 0) + 
                   COALESCE(events.count, 0) + 
                   COALESCE(locations.count, 0) + 
                   COALESCE(donations.count, 0)) > 0
            ORDER BY activity_score DESC, u.created_at ASC
            LIMIT ?
        ''', (limit,))
        
        leaderboard = []
        for i, row in enumerate(c.fetchall(), 1):
            user_data = dict(row)
            user_data['rank'] = i
            user_data['join_date_formatted'] = format_time_ago(user_data['join_date'])
            leaderboard.append(user_data)
        
        conn.close()
        
        return {
            'leaderboard': leaderboard,
            'total_users': len(leaderboard),
            'scoring_system': {
                'posts': 2,
                'damage_reports': 5,
                'events_joined': 3,
                'recovery_locations': 10,
                'donations': 4
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/community/user-stats/{user_id}")
async def get_user_stats(user_id: int):
    """Get detailed stats for a specific user"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get user info
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get all stats
        c.execute('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', (user_id,))
        posts_count = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM damage_reports WHERE CAST(user_id AS INTEGER) = ?', (user_id,))
        reports_count = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM event_volunteers WHERE user_id = ?', (user_id,))
        events_count = c.fetchone()['count']
        
        c.execute('SELECT COUNT(*) as count FROM recovery_locations WHERE CAST(user_id AS INTEGER) = ?', (user_id,))
        locations_count = c.fetchone()['count']
        
        c.execute('''SELECT SUM(d.amount) as total, COUNT(*) as count 
                     FROM donations d 
                     JOIN users u ON d.donor_email = u.email 
                     WHERE u.id = ?''', (user_id,))
        donation_data = c.fetchone()
        
        conn.close()
        
        activity_score = (posts_count * 2 + reports_count * 5 + 
                         events_count * 3 + locations_count * 10 + 
                         (donation_data['count'] or 0) * 4)
        
        return {
            'user': {
                'id': user['id'],
                'name': user['name'],
                'avatar_url': user['avatar_url'],
                'member_since': format_time_ago(user['created_at'])
            },
            'stats': {
                'posts_created': posts_count,
                'damage_reports': reports_count,
                'events_joined': events_count,
                'recovery_locations': locations_count,
                'total_donated': float(donation_data['total'] or 0),
                'donations_made': donation_data['count'] or 0,
                'activity_score': activity_score
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ HELP REQUESTS ENDPOINTS ================

@app.post("/api/help-requests")
async def create_help_request(request: HelpRequestCreate, user_id: int = Depends(verify_token)):
    """Create a new help request"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO help_requests 
                    (user_id, title, location, description, funding_goal, category, urgency)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, request.title, request.location, request.description,
                   request.fundingGoal, request.category, request.urgency))
        
        request_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {"id": request_id, "message": "Help request created"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/help-requests")
async def get_help_requests():
    """Get all help requests"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT hr.*, u.name as author_name
                    FROM help_requests hr
                    JOIN users u ON hr.user_id = u.id
                    ORDER BY hr.created_at DESC''')
        
        requests = []
        for row in c.fetchall():
            request = dict(row)
            request['timePosted'] = format_time_ago(request['created_at'])
            requests.append(request)
        
        conn.close()
        return requests
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ DONATIONS ENDPOINTS ================

@app.post("/api/donations/{help_request_id}")
async def make_donation(help_request_id: int, donation: DonationCreate):
    """Make a donation to a help request"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        # Add donation record
        c.execute('''INSERT INTO donations (help_request_id, donor_name, donor_email, amount)
                    VALUES (?, ?, ?, ?)''',
                  (help_request_id, donation.donorName, donation.email, donation.amount))
        
        # Update funding raised and supporter count
        c.execute('''UPDATE help_requests 
                    SET funding_raised = funding_raised + ?, supporters = supporters + 1
                    WHERE id = ?''',
                  (donation.amount, help_request_id))
        
        conn.commit()
        conn.close()
        
        return {"message": "Donation successful", "amount": donation.amount}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ CHAT ENDPOINTS ================

@app.post("/api/chat")
async def send_chat_message(message: ChatMessage, user_id: int = Depends(verify_token)):
    """Send a chat message"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO chat_messages (user_id, content)
                    VALUES (?, ?)''',
                  (user_id, message.content))
        
        message_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {"id": message_id, "message": "Message sent"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/chat")
async def get_chat_messages(limit: int = Query(50)):
    """Get recent chat messages"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT cm.*, u.name as author_name
                    FROM chat_messages cm
                    JOIN users u ON cm.user_id = u.id
                    ORDER BY cm.created_at DESC
                    LIMIT ?''',
                  (limit,))
        
        messages = []
        for row in c.fetchall():
            message = dict(row)
            message['time'] = format_time_ago(message['created_at'])
            message['avatar'] = message['author_name'][0].upper()
            messages.append(message)
        
        conn.close()
        return list(reversed(messages))  # Return in chronological order
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ VOLUNTEER EVENTS ENDPOINTS ================

@app.post("/api/volunteer-events")
async def create_volunteer_event(event: VolunteerEventCreate, user_id: int = Depends(verify_token)):
    """Create a volunteer event"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO volunteer_events 
                    (user_id, title, location, description, event_date, start_time, end_time, 
                     max_volunteers, category, difficulty)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, event.title, event.location, event.description,
                   event.date, event.startTime, event.endTime, event.maxVolunteers,
                   event.category, event.difficulty))
        
        event_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {"id": event_id, "message": "Event created"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/volunteer-events")
async def get_volunteer_events():
    """Get volunteer events"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT ve.*, u.name as organizer_name
                    FROM volunteer_events ve
                    JOIN users u ON ve.user_id = u.id
                    WHERE ve.event_date >= DATE('now')
                    ORDER BY ve.event_date ASC''')
        
        events = [dict(row) for row in c.fetchall()]
        conn.close()
        return events
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/volunteer-events/{event_id}/join")
async def join_volunteer_event(event_id: int, user_id: int = Depends(verify_token)):
    """Join a volunteer event"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        # Check if already joined
        c.execute('SELECT id FROM event_volunteers WHERE event_id = ? AND user_id = ?', (event_id, user_id))
        if c.fetchone():
            raise HTTPException(status_code=400, detail="Already joined this event")
        
        # Join event
        c.execute('INSERT INTO event_volunteers (event_id, user_id) VALUES (?, ?)', (event_id, user_id))
        c.execute('UPDATE volunteer_events SET current_volunteers = current_volunteers + 1 WHERE id = ?', (event_id,))
        
        conn.commit()
        conn.close()
        
        return {"message": "Successfully joined event"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ AI ANALYSIS ENDPOINTS ================

@app.post("/api/analyze-damage")
async def analyze_damage_polling(photo: UploadFile = File(...)):
    """Queue image for AI analysis using polling system"""
    if not allowed_file(photo.filename):
        raise HTTPException(status_code=400, detail="Invalid file format")
    
    try:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        
        # Read and encode image as base64
        file_data = await photo.read()
        base64_image = base64.b64encode(file_data).decode('utf-8')
        
        print(f"📥 Queuing analysis request: {request_id}")
        
        # Store in analysis queue
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO analysis_queue (request_id, image_data, status)
                    VALUES (?, ?, 'pending')''',
                  (request_id, base64_image))
        
        conn.commit()
        conn.close()
        
        # Wait for result (with timeout)
        max_wait = 60
        wait_time = 0
        
        while wait_time < max_wait:
            await asyncio.sleep(2)
            wait_time += 2
            
            conn = sqlite3.connect('damagesnap.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute('SELECT * FROM analysis_queue WHERE request_id = ?', (request_id,))
            result = c.fetchone()
            conn.close()
            
            if result and result['status'] == 'completed':
                analysis_result = json.loads(result['result'])
                return {
                    'success': True,
                    'ai_analysis': {'analysis': analysis_result},
                    'request_id': request_id,
                    'processing_time': wait_time
                }
            elif result and result['status'] == 'error':
                raise HTTPException(status_code=500, detail={
                    'error': 'AI analysis failed',
                    'details': result['error_message'],
                    'request_id': request_id
                })
        
        # Timeout
        raise HTTPException(status_code=504, detail={
            'error': 'Analysis timeout',
            'details': f'No result after {max_wait} seconds',
            'request_id': request_id,
            'help': 'Check if Colab AI server is running and polling'
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            'error': 'Queue system error', 
            'details': str(e)
        })

@app.get("/api/queue/pending")
async def get_pending_analysis():
    """Get pending analysis requests for Colab server to process"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT request_id, image_data, timestamp 
                    FROM analysis_queue 
                    WHERE status = 'pending' 
                    ORDER BY timestamp ASC 
                    LIMIT 1''')
        
        result = c.fetchone()
        conn.close()
        
        if result:
            return {
                'has_pending': True,
                'request_id': result['request_id'],
                'image_data': result['image_data'],
                'queued_at': result['timestamp']
            }
        else:
            return {'has_pending': False}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/queue/complete")
async def complete_analysis(data: AnalysisResult):
    """Receive analysis results from Colab server"""
    try:
        request_id = data.request_id
        
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        if data.error:
            # Analysis failed
            c.execute('''UPDATE analysis_queue 
                        SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP
                        WHERE request_id = ?''',
                      (data.error, request_id))
            print(f"❌ Analysis failed: {request_id} - {data.error}")
        else:
            # Analysis succeeded
            result_json = json.dumps(data.result or {})
            c.execute('''UPDATE analysis_queue 
                        SET status = 'completed', result = ?, completed_at = CURRENT_TIMESTAMP
                        WHERE request_id = ?''',
                      (result_json, request_id))
            print(f"✅ Analysis completed: {request_id}")
        
        conn.commit()
        conn.close()
        
        return {'success': True}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/queue/status")
async def queue_status():
    """Get queue status information"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) as total FROM analysis_queue')
        total = c.fetchone()['total']
        
        c.execute('SELECT COUNT(*) as pending FROM analysis_queue WHERE status = "pending"')
        pending = c.fetchone()['pending']
        
        c.execute('SELECT COUNT(*) as completed FROM analysis_queue WHERE status = "completed"')
        completed = c.fetchone()['completed']
        
        c.execute('SELECT COUNT(*) as errors FROM analysis_queue WHERE status = "error"')
        errors = c.fetchone()['errors']
        
        conn.close()
        
        return {
            'total_requests': total,
            'pending': pending,
            'completed': completed,
            'errors': errors,
            'queue_system': 'active'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ DAMAGE REPORT ENDPOINTS ================

@app.post("/api/damage-report")
async def create_damage_report(
    user_id: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    damage_score: int = Form(0),
    description: str = Form(""),
    cost_estimate: float = Form(0),
    photo: Optional[UploadFile] = File(None)
):
    """Create a new damage report with photo upload"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        photo_url = None
        if photo and allowed_file(photo.filename):
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secure_filename(photo.filename)}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            with open(file_path, "wb") as buffer:
                content = await photo.read()
                buffer.write(content)
            
            photo_url = f"/uploads/{filename}"
        
        c.execute('''INSERT INTO damage_reports 
                    (user_id, latitude, longitude, photo_url, damage_score, description, cost_estimate)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, latitude, longitude, photo_url, damage_score, description, cost_estimate))
        
        report_id = c.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ Damage report created: ID {report_id}")
        return {'id': report_id, 'message': 'Report created successfully'}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/damage-reports")
async def get_damage_reports(
    lat: float = Query(...),
    lon: float = Query(...),
    radius: float = Query(10)
):
    """Get damage reports in specified area"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT * FROM damage_reports 
                    WHERE latitude BETWEEN ? AND ? 
                    AND longitude BETWEEN ? AND ?
                    ORDER BY timestamp DESC''',
                  (lat - radius/111, lat + radius/111, lon - radius/111, lon + radius/111))
        
        reports = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return reports
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ RECOVERY LOCATION ENDPOINTS ================

@app.post("/api/recovery-location")
async def create_recovery_location(
    user_id: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    volunteers_needed: int = Form(1),
    photo: Optional[UploadFile] = File(None)
):
    """Create a recovery location for community restoration"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        photo_url = None
        if photo and allowed_file(photo.filename):
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secure_filename(photo.filename)}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            with open(file_path, "wb") as buffer:
                content = await photo.read()
                buffer.write(content)
                
            photo_url = f"/uploads/{filename}"
        
        c.execute('''INSERT INTO recovery_locations 
                    (user_id, latitude, longitude, title, description, volunteers_needed, photo_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, latitude, longitude, title, description, volunteers_needed, photo_url))
        
        location_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {'id': location_id, 'message': 'Recovery location created'}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/recovery-locations")
async def get_recovery_locations(
    lat: float = Query(...),
    lon: float = Query(...),
    radius: float = Query(50)
):
    """Get recovery locations needing volunteers"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT rl.*, COUNT(v.id) as volunteer_count 
                    FROM recovery_locations rl 
                    LEFT JOIN volunteers v ON rl.id = v.location_id
                    WHERE rl.latitude BETWEEN ? AND ? 
                    AND rl.longitude BETWEEN ? AND ?
                    AND rl.status = 'active'
                    GROUP BY rl.id
                    ORDER BY rl.timestamp DESC''',
                  (lat - radius/111, lat + radius/111, lon - radius/111, lon + radius/111))
        
        locations = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return locations
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ VOLUNTEER ENDPOINTS ================

@app.post("/api/volunteer")
async def register_volunteer(data: VolunteerRequest):
    """Register as volunteer for a recovery location"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        c = conn.cursor()
        
        c.execute('INSERT INTO volunteers (location_id, user_id, message) VALUES (?, ?, ?)',
                  (data.location_id, data.user_id, data.message))
        
        volunteer_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return {'id': volunteer_id, 'message': 'Volunteer registered'}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/volunteers/{location_id}")
async def get_volunteers(location_id: int):
    """Get list of volunteers for specific location"""
    try:
        conn = sqlite3.connect('damagesnap.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM volunteers WHERE location_id = ? ORDER BY timestamp DESC',
                  (location_id,))
        
        volunteers = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return volunteers
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================ ADMIN/DEBUG ENDPOINTS ================

@app.post("/api/set-ai-server")
async def set_ai_server(data: ServerURL):
    """Update the Colab AI server URL"""
    global COLAB_AI_SERVER
    COLAB_AI_SERVER = data.server_url.rstrip('/')
    return {
        'message': 'AI server URL updated',
        'server_url': COLAB_AI_SERVER
    }

@app.get("/api/ai-server-status")
async def check_ai_server():
    """Check if AI server is available"""
    try:
        response = requests.get(f"{COLAB_AI_SERVER}/health", timeout=5)
        if response.status_code == 200:
            return {
                'status': 'connected',
                'server_url': COLAB_AI_SERVER,
                'ai_server_info': response.json()
            }
        else:
            raise HTTPException(status_code=503, detail={
                'status': 'error',
                'server_url': COLAB_AI_SERVER,
                'error': 'AI server returned error'
            })
    except Exception as e:
        raise HTTPException(status_code=503, detail={
            'status': 'disconnected',
            'server_url': COLAB_AI_SERVER,
            'error': str(e)
        })

@app.get("/api/endpoints")
async def list_endpoints():
    """List all available API endpoints for debugging"""
    endpoints = []
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            endpoints.append({
                'endpoint': route.path,
                'methods': list(route.methods - {'HEAD', 'OPTIONS'}),
                'function': route.name
            })
    
    return {
        'total_endpoints': len(endpoints),
        'endpoints': sorted(endpoints, key=lambda x: x['endpoint'])
    }

@app.get("/api/debug")
async def debug_info():
    """Debug information for troubleshooting"""
    try:
        # Test AI server connection
        ai_status = "Not configured"
        ai_response_time = None
        
        if COLAB_AI_SERVER and COLAB_AI_SERVER != "http://your-colab-url:5000":
            try:
                start_time = time.time()
                response = requests.get(f"{COLAB_AI_SERVER}/health", timeout=5)
                ai_response_time = round((time.time() - start_time) * 1000, 2)
                
                if response.status_code == 200:
                    ai_status = f"Connected ({ai_response_time}ms)"
                else:
                    ai_status = f"Error: HTTP {response.status_code}"
            except requests.exceptions.Timeout:
                ai_status = "Timeout (>5s)"
            except requests.exceptions.ConnectionError:
                ai_status = "Connection failed"
            except Exception as e:
                ai_status = f"Error: {str(e)}"
        
        return {
            "database_server": {
                "status": "Running",
                "version": "3.1 (Complete FastAPI + Leaderboard)"
            },
            "ai_server": {
                "url": COLAB_AI_SERVER,
                "status": ai_status,
                "response_time_ms": ai_response_time
            },
            "features": {
                "authentication": "✅ Enabled",
                "posts": "✅ Enabled",
                "help_requests": "✅ Enabled",
                "donations": "✅ Enabled",
                "chat": "✅ Enabled",
                "volunteer_events": "✅ Enabled",
                "ai_analysis": "✅ Enabled",
                "leaderboard": "✅ Enabled"
            },
            "configuration": {
                "upload_folder": UPLOAD_FOLDER,
                "max_file_size": f"{MAX_CONTENT_LENGTH / (1024*1024)}MB"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Debug failed: {str(e)}")

if __name__ == '__main__':
    init_db()
    
    # Check if running with SSL
    ssl_keyfile = '/etc/letsencrypt/live/db.xoperr.dev/privkey.pem'
    ssl_certfile = '/etc/letsencrypt/live/db.xoperr.dev/fullchain.pem'
    
    if os.path.exists(ssl_keyfile) and os.path.exists(ssl_certfile):
        print("🔒 Starting with SSL on port 443")
        uvicorn.run(app, host='0.0.0.0', port=443, 
                    ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile)
    else:
        print("⚠️  SSL certificates not found, starting HTTP on port 8000")
        print("🚀 Complete DamageSnap API Server starting...")
        print("📋 Features: Auth, Posts, Help Requests, Donations, Chat, Events, AI Analysis, Leaderboard")
        uvicorn.run(app, host='0.0.0.0', port=8000)
