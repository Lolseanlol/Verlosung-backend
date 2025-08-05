from fastapi import FastAPI, Depends, HTTPException, Request, status, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo import MongoClient
from typing import Optional, List, Dict, Any
import os
import httpx
import hmac
import hashlib
import secrets
import json
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'giveaway_database')
TWITCH_CLIENT_ID = "ftjahnhpm23mx19o8wxjbrmzak1f3m"
TWITCH_CLIENT_SECRET = "5h2nhzo70zx26hkyadpfykdtaqv3ws"
TWITCH_REDIRECT_URI = "https://eb1b5aa2-2ec2-4e14-aec3-27580ab277b3.preview.emergentagent.com/auth/callback"
TWITCH_WEBHOOK_SECRET = secrets.token_urlsafe(32)
TWITCH_CALLBACK_URL = "https://eb1b5aa2-2ec2-4e14-aec3-27580ab277b3.preview.emergentagent.com/api/webhooks/twitch"
ADMIN_USERNAME = "vor_texz"

# FastAPI app initialization
app = FastAPI(title="Twitch Giveaway Platform", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Database setup
try:
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]
    
    # Collections
    users_collection = db['users']
    giveaways_collection = db['giveaways']
    entries_collection = db['giveaway_entries']
    events_collection = db['twitch_events']
    
    # Create indexes
    users_collection.create_index("twitch_user_id", unique=True)
    giveaways_collection.create_index("created_at")
    entries_collection.create_index([("giveaway_id", 1), ("user_id", 1)])
    
    logger.info("Database connected successfully")
except Exception as e:
    logger.error(f"Database connection failed: {e}")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Pydantic models
class GiveawayCreate(BaseModel):
    title: str
    description: str
    rules: str
    duration_hours: int
    entry_types: List[str]  # ["subscriptions", "bits"]
    bits_per_entry: Optional[int] = 500
    max_entries_per_user: Optional[int] = None

class GiveawayEntry(BaseModel):
    user_id: str
    giveaway_id: str
    entry_type: str  # "subscription" or "bits"
    tickets: int
    entry_data: Dict = {}

# Twitch OAuth implementation
class TwitchOAuth:
    def __init__(self):
        self.client_id = TWITCH_CLIENT_ID
        self.client_secret = TWITCH_CLIENT_SECRET
        self.redirect_uri = TWITCH_REDIRECT_URI
        self.auth_url = "https://id.twitch.tv/oauth2/authorize"
        self.token_url = "https://id.twitch.tv/oauth2/token"
        self.validate_url = "https://id.twitch.tv/oauth2/validate"
        self.users_url = "https://api.twitch.tv/helix/users"

    def get_auth_url(self, scopes: list = None, state: str = None):
        if scopes is None:
            scopes = ["user:read:email", "channel:read:subscriptions", "bits:read"]
        
        if state is None:
            state = secrets.token_urlsafe(32)
            
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
            "force_verify": "false"
        }
        
        return f"{self.auth_url}?{urlencode(params)}", state

    async def exchange_code_for_token(self, code: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(status_code=400, detail="Token exchange failed")

    async def get_user_info(self, access_token: str):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Client-Id": self.client_id
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(self.users_url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return None

    async def get_app_access_token(self):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            if response.status_code == 200:
                token_data = response.json()
                return token_data["access_token"]
            else:
                raise Exception("Failed to get app access token")

twitch_oauth = TwitchOAuth()

# Session management
user_sessions = {}
pending_auth_states = {}

# EventSub webhook handling
class TwitchEventSub:
    def __init__(self):
        self.client_id = TWITCH_CLIENT_ID
        self.client_secret = TWITCH_CLIENT_SECRET
        self.callback_url = TWITCH_CALLBACK_URL
        self.webhook_secret = TWITCH_WEBHOOK_SECRET
        self.eventsub_url = "https://api.twitch.tv/helix/eventsub/subscriptions"
        self.app_token = None

    def verify_signature(self, request_body: bytes, headers: dict) -> bool:
        message_id = headers.get("twitch-eventsub-message-id")
        timestamp = headers.get("twitch-eventsub-message-timestamp")
        signature = headers.get("twitch-eventsub-message-signature")
        
        if not all([message_id, timestamp, signature]):
            return False
        
        # Check timestamp to prevent replay attacks
        try:
            msg_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) - msg_time > timedelta(minutes=10):
                return False
        except:
            return False
        
        # Construct message for verification
        message = message_id + timestamp + request_body.decode('utf-8')
        
        # Generate expected signature
        expected_signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        expected_signature = f"sha256={expected_signature}"
        
        return hmac.compare_digest(expected_signature, signature)

    async def handle_webhook(self, request: Request, background_tasks: BackgroundTasks):
        body = await request.body()
        headers = dict(request.headers)
        
        # Verify signature
        if not self.verify_signature(body, headers):
            raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Parse notification
        try:
            notification = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON")
        
        message_type = headers.get("twitch-eventsub-message-type")
        
        if message_type == "webhook_callback_verification":
            # Return challenge for subscription verification
            return Response(
                content=notification["challenge"],
                media_type="text/plain",
                status_code=200
            )
        
        elif message_type == "notification":
            # Handle actual event notification
            event_type = notification["subscription"]["type"]
            event_data = notification["event"]
            
            # Process event in background
            background_tasks.add_task(self.process_event, event_type, event_data, notification)
            
            return Response(status_code=200)
        
        elif message_type == "revocation":
            # Handle subscription revocation
            logger.info(f"Subscription revoked: {notification}")
            return Response(status_code=200)
        
        else:
            raise HTTPException(status_code=400, detail="Unknown message type")

    async def process_event(self, event_type: str, event_data: dict, notification: dict):
        """Process Twitch events and handle giveaway entries"""
        try:
            # Store the event
            event_record = {
                "id": str(uuid.uuid4()),
                "event_type": event_type,
                "event_data": event_data,
                "notification": notification,
                "processed_at": datetime.utcnow(),
                "processed": False
            }
            events_collection.insert_one(event_record)

            # Process based on event type
            if event_type == "channel.subscribe":
                await self.handle_subscription_event(event_data)
            elif event_type == "channel.cheer":
                await self.handle_bits_event(event_data)
            
            # Mark as processed
            events_collection.update_one(
                {"id": event_record["id"]},
                {"$set": {"processed": True}}
            )
            
        except Exception as e:
            logger.error(f"Error processing event {event_type}: {str(e)}")

    async def handle_subscription_event(self, event_data: dict):
        """Handle subscription events for giveaway entries"""
        user_id = event_data.get("user_id")
        user_name = event_data.get("user_name")
        tier = event_data.get("tier", "1000")
        
        # Get active giveaways that accept subscriptions
        active_giveaways = list(giveaways_collection.find({
            "status": "active",
            "entry_types": "subscriptions",
            "end_time": {"$gt": datetime.utcnow()}
        }))
        
        for giveaway in active_giveaways:
            # Calculate tickets based on tier
            tickets = 1
            if tier == "2000":
                tickets = 2
            elif tier == "3000":
                tickets = 3
            
            # Check if user already has entries for this giveaway
            existing_entry = entries_collection.find_one({
                "giveaway_id": giveaway["id"],
                "user_id": user_id
            })
            
            if existing_entry:
                # Update existing entry
                entries_collection.update_one(
                    {"_id": existing_entry["_id"]},
                    {"$inc": {"tickets": tickets}}
                )
            else:
                # Create new entry
                entry = {
                    "id": str(uuid.uuid4()),
                    "giveaway_id": giveaway["id"],
                    "user_id": user_id,
                    "user_name": user_name,
                    "entry_type": "subscription",
                    "tickets": tickets,
                    "entry_data": {"tier": tier},
                    "created_at": datetime.utcnow()
                }
                entries_collection.insert_one(entry)
            
            logger.info(f"Added {tickets} tickets for {user_name} via subscription (tier {tier})")

    async def handle_bits_event(self, event_data: dict):
        """Handle bits events for giveaway entries"""
        user_id = event_data.get("user_id")
        user_name = event_data.get("user_name")
        bits = int(event_data.get("bits", 0))
        
        # Get active giveaways that accept bits
        active_giveaways = list(giveaways_collection.find({
            "status": "active",
            "entry_types": "bits",
            "end_time": {"$gt": datetime.utcnow()}
        }))
        
        for giveaway in active_giveaways:
            bits_per_entry = giveaway.get("bits_per_entry", 500)
            tickets = bits // bits_per_entry  # Per-donation calculation as requested
            
            if tickets > 0:
                # Check if user already has entries for this giveaway
                existing_entry = entries_collection.find_one({
                    "giveaway_id": giveaway["id"],
                    "user_id": user_id
                })
                
                if existing_entry:
                    # Update existing entry
                    entries_collection.update_one(
                        {"_id": existing_entry["_id"]},
                        {"$inc": {"tickets": tickets}}
                    )
                else:
                    # Create new entry
                    entry = {
                        "id": str(uuid.uuid4()),
                        "giveaway_id": giveaway["id"],
                        "user_id": user_id,
                        "user_name": user_name,
                        "entry_type": "bits",
                        "tickets": tickets,
                        "entry_data": {"bits": bits, "bits_per_entry": bits_per_entry},
                        "created_at": datetime.utcnow()
                    }
                    entries_collection.insert_one(entry)
                
                logger.info(f"Added {tickets} tickets for {user_name} via {bits} bits")

eventsub = TwitchEventSub()

# Authentication dependencies
async def get_current_user(session_id: Optional[str] = Depends(oauth2_scheme)):
    if not session_id or session_id not in user_sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_sessions[session_id]

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

# Authentication endpoints
@app.get("/api/auth/login")
async def login():
    auth_url, state = twitch_oauth.get_auth_url()
    pending_auth_states[state] = True
    return {"auth_url": auth_url, "state": state}

@app.get("/api/auth/callback")
async def auth_callback(code: str, state: str, error: Optional[str] = None):
    if error:
        raise HTTPException(status_code=400, detail=f"Authorization failed: {error}")
    
    if state not in pending_auth_states:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    del pending_auth_states[state]
    
    try:
        token_data = await twitch_oauth.exchange_code_for_token(code)
        user_info = await twitch_oauth.get_user_info(token_data["access_token"])
        
        if not user_info or "data" not in user_info:
            raise HTTPException(status_code=400, detail="Failed to get user information")
        
        user_data = user_info["data"][0]
        session_id = secrets.token_urlsafe(32)
        
        is_admin = user_data["login"].lower() == ADMIN_USERNAME.lower()
        
        # Store/update user in database
        user_record = {
            "twitch_user_id": user_data["id"],
            "username": user_data["login"],
            "display_name": user_data["display_name"],
            "email": user_data.get("email"),
            "is_admin": is_admin,
            "last_login": datetime.utcnow()
        }
        
        users_collection.update_one(
            {"twitch_user_id": user_data["id"]},
            {"$set": user_record},
            upsert=True
        )
        
        user_sessions[session_id] = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "user_id": user_data["id"],
            "username": user_data["login"],
            "display_name": user_data["display_name"],
            "email": user_data.get("email"),
            "is_admin": is_admin,
            "scopes": token_data.get("scope", [])
        }
        
        return {
            "session_id": session_id,
            "user": user_data,
            "is_admin": is_admin
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return {
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "display_name": current_user["display_name"],
        "email": current_user.get("email"),
        "is_admin": current_user["is_admin"]
    }

# Giveaway endpoints
@app.post("/api/admin/giveaways")
async def create_giveaway(giveaway: GiveawayCreate, admin_user: dict = Depends(get_admin_user)):
    giveaway_data = {
        "id": str(uuid.uuid4()),
        "title": giveaway.title,
        "description": giveaway.description,
        "rules": giveaway.rules,
        "duration_hours": giveaway.duration_hours,
        "entry_types": giveaway.entry_types,
        "bits_per_entry": giveaway.bits_per_entry,
        "max_entries_per_user": giveaway.max_entries_per_user,
        "status": "active",
        "created_by": admin_user["user_id"],
        "created_at": datetime.utcnow(),
        "end_time": datetime.utcnow() + timedelta(hours=giveaway.duration_hours),
        "winner": None
    }
    
    result = giveaways_collection.insert_one(giveaway_data)
    giveaway_data["_id"] = str(result.inserted_id)
    
    return giveaway_data

@app.get("/api/giveaways")
async def get_giveaways():
    giveaways = list(giveaways_collection.find(
        {"status": {"$in": ["active", "completed"]}},
        {"_id": 0}
    ).sort("created_at", -1))
    
    # Add participant counts
    for giveaway in giveaways:
        participant_count = entries_collection.count_documents({"giveaway_id": giveaway["id"]})
        total_tickets = list(entries_collection.aggregate([
            {"$match": {"giveaway_id": giveaway["id"]}},
            {"$group": {"_id": None, "total": {"$sum": "$tickets"}}}
        ]))
        
        giveaway["participant_count"] = participant_count
        giveaway["total_tickets"] = total_tickets[0]["total"] if total_tickets else 0
    
    return giveaways

@app.get("/api/giveaways/{giveaway_id}")
async def get_giveaway(giveaway_id: str):
    giveaway = giveaways_collection.find_one({"id": giveaway_id}, {"_id": 0})
    if not giveaway:
        raise HTTPException(status_code=404, detail="Giveaway not found")
    
    # Get participants
    participants = list(entries_collection.find(
        {"giveaway_id": giveaway_id},
        {"_id": 0}
    ).sort("created_at", -1))
    
    giveaway["participants"] = participants
    giveaway["participant_count"] = len(participants)
    giveaway["total_tickets"] = sum(p["tickets"] for p in participants)
    
    return giveaway

@app.post("/api/admin/giveaways/{giveaway_id}/end")
async def end_giveaway(giveaway_id: str, admin_user: dict = Depends(get_admin_user)):
    giveaway = giveaways_collection.find_one({"id": giveaway_id})
    if not giveaway:
        raise HTTPException(status_code=404, detail="Giveaway not found")
    
    giveaways_collection.update_one(
        {"id": giveaway_id},
        {"$set": {"status": "ended", "ended_at": datetime.utcnow()}}
    )
    
    return {"message": "Giveaway ended successfully"}

@app.post("/api/admin/giveaways/{giveaway_id}/winner")
async def select_winner(giveaway_id: str, admin_user: dict = Depends(get_admin_user)):
    giveaway = giveaways_collection.find_one({"id": giveaway_id})
    if not giveaway:
        raise HTTPException(status_code=404, detail="Giveaway not found")
    
    # Get all entries with their ticket weights
    entries = list(entries_collection.find({"giveaway_id": giveaway_id}))
    if not entries:
        raise HTTPException(status_code=400, detail="No entries found for this giveaway")
    
    # Create weighted list for random selection
    weighted_entries = []
    for entry in entries:
        for _ in range(entry["tickets"]):
            weighted_entries.append(entry)
    
    # Select random winner
    import random
    winner_entry = random.choice(weighted_entries)
    
    # Update giveaway with winner
    giveaways_collection.update_one(
        {"id": giveaway_id},
        {
            "$set": {
                "winner": {
                    "user_id": winner_entry["user_id"],
                    "user_name": winner_entry["user_name"],
                    "tickets": winner_entry["tickets"],
                    "entry_type": winner_entry["entry_type"]
                },
                "status": "completed",
                "completed_at": datetime.utcnow()
            }
        }
    )
    
    return {
        "winner": winner_entry,
        "total_participants": len(entries),
        "total_tickets": len(weighted_entries)
    }

@app.get("/api/user/entries")
async def get_user_entries(current_user: dict = Depends(get_current_user)):
    entries = list(entries_collection.find(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    ).sort("created_at", -1))
    
    # Add giveaway info to each entry
    for entry in entries:
        giveaway = giveaways_collection.find_one({"id": entry["giveaway_id"]}, {"_id": 0})
        entry["giveaway"] = giveaway
    
    return entries

# EventSub webhook endpoint
@app.post("/api/webhooks/twitch")
async def twitch_webhook(request: Request, background_tasks: BackgroundTasks):
    return await eventsub.handle_webhook(request, background_tasks)

# Admin endpoints
@app.get("/api/admin/users")
async def list_users(admin_user: dict = Depends(get_admin_user)):
    users = list(users_collection.find({}, {"_id": 0}).sort("last_login", -1))
    return users

@app.get("/api/admin/events")
async def list_events(admin_user: dict = Depends(get_admin_user)):
    events = list(events_collection.find({}, {"_id": 0}).sort("processed_at", -1).limit(100))
    return events

# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)