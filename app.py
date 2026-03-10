import base64
import warnings
warnings.filterwarnings("ignore", category=FutureWarning) # Hides Google SDK deprecation warnings
import io
import os
import re
import sys
import json
import subprocess
import urllib.parse
from urllib.parse import urlparse
from datetime import datetime, date, timedelta
import uuid
import random
from threading import Thread

import docx
import fitz  # PyMuPDF
import google.generativeai as genai
import requests
from flask import (Flask, jsonify, render_template, request, session, redirect,
                   url_for, flash, make_response)
from flask_cors import CORS
from PIL import Image
from pymongo import MongoClient
from bson.objectid import ObjectId
from youtube_transcript_api import YouTubeTranscriptApi
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)

app = Flask(__name__, template_folder='templates')
CORS(app)

# --- Configuration ---
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key") 
app.config['SECRET_KEY'] = SECRET_KEY
if SECRET_KEY == "dev-secret-key":
    print("CRITICAL WARNING: Using a default, insecure FLASK_SECRET_KEY for development.")

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY")
MONGO_URI = os.environ.get("MONGO_URI")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
SERPER_API_KEY = os.environ.get("SERPER_API_KEY")
NVD_API_KEY = os.environ.get("NVD_API_KEY") # NEW: NVD API Key

# --- Brevo (Email) Configuration ---
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "admin@sofia-ai.com")

if not BREVO_API_KEY:
    print("CRITICAL WARNING: BREVO_API_KEY not found. Email features will not work.")

# --- API Services Configuration ---
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    print(f"✅ Loaded google-generativeai version: {genai.__version__}")
else:
    print("CRITICAL ERROR: GOOGLE_API_KEY environment variable not found.")

if YOUTUBE_API_KEY:
    print("✅ YouTube API Key loaded.")
else:
    print("CRITICAL WARNING: YOUTUBE_API_KEY not found. YouTube features will be disabled.")

if SERPER_API_KEY:
    print("✅ Serper API Key (for web search) loaded.")
else:
    print("CRITICAL WARNING: SERPER_API_KEY not found. AI web search will be disabled.")

# --- MongoDB Configuration ---
mongo_client = None
chat_history_collection = None
temporary_chat_collection = None
conversations_collection = None
users_collection = None
library_collection = None
feedback_collection = None

if MONGO_URI:
    try:
        mongo_client = MongoClient(MONGO_URI)
        db = mongo_client.get_database("ai_assistant_db")
        db.command('ping')
        print("✅ Successfully pinged MongoDB.")
        
        chat_history_collection = db.get_collection("chat_history")
        temporary_chat_collection = db.get_collection("temporary_chats")
        conversations_collection = db.get_collection("conversations")
        users_collection = db.get_collection("users")
        library_collection = db.get_collection("library_items")
        feedback_collection = db.get_collection("feedback")
        print("✅ Successfully connected to MongoDB with feedback collection.")
    except Exception as e:
        print(f"CRITICAL ERROR: Could not connect to MongoDB. Error: {e}")
else:
    print("CRITICAL WARNING: MONGO_URI not found. Data will not be saved.")

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.email = user_data.get("email")
        self.name = user_data.get("name")
        self.isAdmin = user_data.get("isAdmin", False)
        self.isPremium = user_data.get("isPremium", False)
        self.session_id = user_data.get("session_id")
        self.is_verified = user_data.get("is_verified", False)

    @staticmethod
    def get(user_id):
        if users_collection is None:
            return None
        try:
            user_data = users_collection.find_one({"_id": ObjectId(user_id)})
            return User(user_data) if user_data else None
        except Exception as e:
            print(f"USER_GET_ERROR: Failed to get user {user_id}. Error: {e}")
            return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.before_request
def before_request_callback():
    if current_user.is_authenticated:
        if session.get('session_id') != current_user.session_id:
            logout_user()
            flash("You have been logged out from another device.", "info")
            return redirect(url_for('login_page'))

# --- GitHub Configuration ---
GITHUB_USER = os.environ.get("GITHUB_USER")
GITHUB_REPO = os.environ.get("GITHUB_REPO")
GITHUB_FOLDER_PATH = os.environ.get("GITHUB_FOLDER_PATH", "")
PDF_KEYWORDS = {} # Configure your keywords here

# --- Helper: Send Email via Brevo ---
def send_brevo_email(to_email, subject, html_content):
    if not BREVO_API_KEY:
        print(f"❌ EMAIL ERROR: BREVO_API_KEY is not configured. Cannot send email to {to_email}")
        return False
    if not SENDER_EMAIL:
        print(f"❌ EMAIL ERROR: SENDER_EMAIL is not configured.")
        return False
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"email": SENDER_EMAIL, "name": "Sofia AI"},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code in [401, 400, 403, 429]:
            print(f"❌ BREVO EMAIL ERROR: Status {response.status_code}")
            return False
        response.raise_for_status()
        print(f"✅ Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ BREVO EMAIL ERROR for {to_email}: {str(e)}")
        return False

def send_async_brevo_email(app, to_email, subject, html_content):
    with app.app_context():
        send_brevo_email(to_email, subject, html_content)

# --- NEW HELPER: Fetch CVE from NVD ---
def get_cve_from_nvd(vuln_name):
    """Searches the NIST NVD database for a related CVE based on ZAP alert name."""
    try:
        # Clean up the name for better search results (limit length to avoid huge queries)
        search_term = urllib.parse.quote(vuln_name[:50])
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=1"
        
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        # 3 second timeout so we don't block Render's 100s limit
        response = requests.get(url, headers=headers, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                return data["vulnerabilities"][0]["cve"]["id"]
    except Exception as e:
        print(f"NVD API Error for '{vuln_name}': {e}")
    return None

# --- Helper Functions ---
def validate_file_size(file_data, max_size_mb=10):
    size_bytes = len(file_data) * 3 / 4
    size_mb = size_bytes / (1024 * 1024)
    if size_mb > max_size_mb:
        return False, f"File too large ({size_mb:.2f}MB). Max size is {max_size_mb}MB."
    return True, None

def detect_code_language(filename, content):
    extension_map = {
        '.py': 'Python', '.js': 'JavaScript', '.java': 'Java', '.c': 'C', '.cpp': 'C++',
        '.h': 'C/C++ Header', '.html': 'HTML', '.css': 'CSS', '.json': 'JSON', '.md': 'Markdown',
        '.sh': 'Shell Script', '.rb': 'Ruby', '.go': 'Go', '.php': 'PHP', '.swift': 'Swift',
        '.kt': 'Kotlin', '.ts': 'TypeScript', '.jsx': 'React JSX', '.tsx': 'React TSX',
        '.vue': 'Vue.js', '.pl': 'Perl', '.r': 'R', '.scala': 'Scala', '.rs': 'Rust',
        '.ex': 'Elixir', '.exs': 'Elixir Script', '.erl': 'Erlang'
    }
    for ext, lang in extension_map.items():
        if filename.lower().endswith(ext):
            return lang
    if '<?php' in content[:100]: return 'PHP'
    elif 'def ' in content[:100] or 'import ' in content[:100]: return 'Python'
    elif 'function' in content[:100] or 'const ' in content[:100] or 'let ' in content[:100]: return 'JavaScript'
    elif 'public class' in content[:100]: return 'Java'
    elif '#include' in content[:100]: return 'C/C++'
    elif '<!DOCTYPE html>' in content[:100] or '<html' in content[:100]: return 'HTML'
    return 'Unknown'

def extract_text_from_pdf(pdf_bytes):
    try:
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        return "".join(page.get_text() for page in pdf_document)
    except Exception as e:
        print(f"Error extracting PDF text: {e}")
        return ""

def extract_text_from_docx(docx_bytes):
    try:
        document = docx.Document(io.BytesIO(docx_bytes))
        return "\n".join([para.text for para in document.paragraphs])
    except Exception as e:
        print(f"Error extracting DOCX text: {e}")
        return ""

def get_video_id(video_url):
    match = re.search(r"(?:v=|\/|youtu\.be\/)([a-zA-Z0-9_-]{11})", video_url)
    return match.group(1) if match else None

def get_youtube_transcript(video_id):
    try:
        return " ".join([d['text'] for d in YouTubeTranscriptApi.get_transcript(video_id)])
    except Exception as e:
        print(f"Error getting YouTube transcript: {e}")
        return None

def call_api(url, headers, json_payload, api_name):
    try:
        response = requests.post(url, headers=headers, json=json_payload)
        response.raise_for_status()
        result = response.json()
        if 'choices' in result and len(result['choices']) > 0 and 'message' in result['choices'][0] and 'content' in result['choices'][0]['message']:
             return result['choices'][0]['message']['content']
        else:
            return None
    except Exception as e:
        print(f"Error calling {api_name} API: {e}")
        return None

def search_web(query):
    if not SERPER_API_KEY:
        return "Web search is disabled because the API key is not configured."
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query})
    headers = {'X-API-KEY': SERPER_API_KEY, 'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        results = response.json()
        snippets = []
        if "organic" in results:
            for item in results.get("organic", [])[:5]:
                snippets.append(f"Title: {item.get('title', 'No Title')}\nSnippet: {item.get('snippet', 'No Snippet')}\nSource: {item.get('link', 'No Link')}")
        if snippets:
            return "\n\n---\n\n".join(snippets)
        elif "answerBox" in results:
            answer = results["answerBox"].get("snippet") or results["answerBox"].get("answer")
            if answer: return f"Direct Answer: {answer}"
        return "No relevant web results found."
    except Exception as e:
        return f"An error occurred during the web search: {e}"

def search_library(user_id, query):
    if not library_collection: return None
    try:
        keywords = re.split(r'\s+', query)
        regex_pattern = '.*'.join(f'(?=.*{re.escape(k)})' for k in keywords)
        items_cursor = library_collection.find({
            "user_id": user_id,
            "extracted_text": {"$regex": regex_pattern, "$options": "i"}
        }).limit(3)
        snippets = []
        for item in items_cursor:
            snippets.append(f"Source: {item.get('filename', 'Untitled')} (from your Library)\nSnippet: {item.get('extracted_text', '')[:300]}...")
        if snippets: return "\n\n---\n\n".join(snippets)
        return None
    except Exception as e:
        return None

def should_auto_search(user_message):
    msg_lower = user_message.lower().strip()
    security_keywords = ['vulnerability', 'malware', 'cybersecurity', 'sql injection', 'xss', 'mitigation', 'exploit']
    code_keywords = ['def ', 'function ', 'public class', 'SELECT *', 'import ', 'require(']
    general_search_keywords = ['what is', 'who is', 'where is', 'latest', 'news', 'in 2025']
    chat_keywords = ['hi', 'hello', 'thanks']
    if any(msg_lower.startswith(k) for k in chat_keywords): return None
    if any(k in msg_lower for k in security_keywords): return 'security_search'
    if any(k in user_message for k in code_keywords): return 'code_security_scan'
    if any(k in msg_lower for k in general_search_keywords): return 'web_search'
    if len(user_message.split()) > 6: return 'web_search'
    return None

def get_ai_summary(text_content):
    if not GOOGLE_API_KEY or not text_content or text_content.isspace():
        return "Summary generation skipped."
    try:
        model = genai.GenerativeModel("gemini-2.5-flash-lite") 
        prompt = f"As Sofia AI, please provide a concise, one-paragraph summary:\n\n{text_content[:80000]}"
        return model.generate_content(prompt).text
    except Exception as e:
        return f"Could not generate summary. Error: {e}"

def run_ai_summary_in_background(app, item_id, text_content):
    with app.app_context():
        summary = get_ai_summary(text_content)
        if library_collection:
            try:
                library_collection.update_one({"_id": ObjectId(item_id)}, {"$set": {"ai_summary": summary, "ai_summary_status": "completed"}})
            except Exception as e:
                print(f"BACKGROUND_MONGO_ERROR: {e}")

def handle_greetings_and_introductions(message):
    message_lower = message.lower().strip()
    greeting_responses = {
        'hi': "Hello! I'm Sofia AI, your Security-Focused Multimodal Assistant. How can I help you today?",
        'hello': "Hi there! I'm Sofia AI, ready to help with security analysis and more. What can I assist you with?",
        'who are you': "I'm Sofia AI - a Security-Focused Multimodal Assistant. I specialize in security analysis, threat detection, code scanning, and secure development practices."
    }
    for key, response in greeting_responses.items():
        if message_lower == key or message_lower.startswith(key + ' '):
            return response
    if any(word in message_lower for word in ['hi ', 'hello ', 'hey ']):
        return "Hello! I'm Sofia AI. How can I assist you today?"
    return None

# --- Page Rendering Routes ---
@app.route('/')
@login_required
def home():
    if not current_user.is_verified:
        logout_user()
        return redirect(url_for('login_page', error="Please verify your email address."))
    return render_template('index.html') 

@app.route('/login.html', methods=['GET'])
def login_page(): return redirect(url_for('home')) if current_user.is_authenticated else render_template('login.html')

@app.route('/signup.html', methods=['GET'])
def signup_page(): return redirect(url_for('home')) if current_user.is_authenticated else render_template('signup.html')

@app.route('/website.html', methods=['GET'])
def website_page(): return render_template('website.html')

@app.route('/login')
def login_redirect(): return redirect(url_for('login_page'))

@app.route('/signup')
def signup_redirect(): return redirect(url_for('signup_page'))
  
@app.route('/reset-password')
def reset_password_page(): return render_template('reset_password.html')

# --- API Authentication Routes ---
@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    name, email, password = data.get('name'), data.get('email'), data.get('password')
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")

    if not all([name, email, password]): return jsonify({'success': False, 'error': 'Please fill out all fields.'}), 400
    if users_collection is None: return jsonify({'success': False, 'error': 'Database not configured.'}), 500
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email): return jsonify({'success': False, 'error': 'Invalid email format.'}), 400
    if users_collection.find_one({"email": email}): return jsonify({'success': False, 'error': 'An account with this email already exists.'}), 409

    otp_code = str(random.randint(100000, 999999))
    new_user = {
        "name": name, "email": email, "password": password, "isAdmin": email == ADMIN_EMAIL, 
        "isPremium": False, "is_verified": False, "verification_token": otp_code,
        "session_id": str(uuid.uuid4()), "usage_counts": { "messages": 0, "webSearches": 0, "feedback": 0 },
        "last_usage_reset": datetime.utcnow().strftime('%Y-%m-%d'), "last_web_reset": datetime.utcnow().strftime('%Y-%m-%d'),
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        users_collection.insert_one(new_user)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Database error. Please try again.'}), 500

    html_content = f"<h2>Welcome to Sofia AI, {name}!</h2><p>Your verification code is: <strong>{otp_code}</strong></p>"
    Thread(target=send_async_brevo_email, args=(app, email, "Your Sofia AI Verification Code", html_content)).start()
    return jsonify({'success': True, 'message': 'OTP sent! Please check your email.'})

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    data = request.get_json()
    email, otp = data.get('email'), data.get('otp')
    if not all([email, otp]): return jsonify({'success': False, 'error': 'Email and OTP are required.'}), 400
    user = users_collection.find_one({"email": email, "verification_token": otp})
    if not user: return jsonify({'success': False, 'error': 'Invalid or incorrect OTP.'}), 400
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}, "$unset": {"verification_token": 1}})
    return jsonify({'success': True, 'message': 'Account verified successfully!'})

@app.route('/api/resend_otp', methods=['POST'])
def api_resend_otp():
    email = request.get_json().get('email')
    if not email: return jsonify({'success': False, 'error': 'Email is required.'}), 400
    user = users_collection.find_one({"email": email})
    if not user: return jsonify({'success': True, 'message': 'If an account exists, a new OTP has been sent.'})
    if user.get('is_verified', False): return jsonify({'success': False, 'error': 'Account is already verified.'}), 400
    
    new_otp = str(random.randint(100000, 999999))
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"verification_token": new_otp}})
    html_content = f"<h2>Sofia AI Verification</h2><p>Your new OTP is: <strong>{new_otp}</strong></p>"
    Thread(target=send_async_brevo_email, args=(app, email, "New Verification Code", html_content)).start()
    return jsonify({'success': True, 'message': 'New OTP sent! Please check your email.'})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not all([email, password]): return jsonify({'success': False, 'error': 'Please enter both email and password.'}), 400
    
    user_data = users_collection.find_one({"email": email})
    if user_data and user_data.get('password') == password:
        if not user_data.get('is_verified', False): return jsonify({'success': False, 'error': 'Please verify your email address first.'}), 403
        new_session_id = str(uuid.uuid4())
        users_collection.update_one({'_id': user_data['_id']}, {'$set': {'session_id': new_session_id}})
        user_data['session_id'] = new_session_id
        login_user(User(user_data))
        session['session_id'] = new_session_id
        return jsonify({'success': True, 'user': {'name': user_data['name'], 'email': user_data['email']}})
    return jsonify({'success': False, 'error': 'Incorrect email or password.'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

# --- Usage Tracking API ---
@app.route('/update_usage', methods=['POST'])
@login_required
def update_usage():
    if users_collection is None: return jsonify({'success': False, 'error': 'Database not configured'}), 500
    usage_type = request.get_json().get('type')
    update_field = 'usage_counts.messages' if usage_type == 'message' else ('usage_counts.webSearches' if usage_type == 'web_search' else 'usage_counts.feedback')
    users_collection.update_one({'_id': ObjectId(current_user.id)}, {'$inc': {update_field: 1}})
    return jsonify({'success': True})

# --- Chat Logic with Security Focus ---
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    # Free plan usage check
    if not current_user.isPremium and not current_user.isAdmin:
        user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
        today = datetime.utcnow().date()
        last_reset_date = datetime.strptime(user_data.get('last_usage_reset', '1970-01-01'), '%Y-%m-%d').date()
        
        if last_reset_date.month < today.month or last_reset_date.year < today.year:
            users_collection.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'usage_counts.messages': 0, 'last_usage_reset': today.strftime('%Y-%m-%d')}})
            user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
            
        if user_data.get('usage_counts', {}).get('messages', 0) >= 500:
            return jsonify({'error': 'You have reached your monthly message limit. Please upgrade.', 'upgrade_required': True}), 429
        users_collection.update_one({'_id': ObjectId(current_user.id)}, {'$inc': {'usage_counts.messages': 1}})

    try:
        data = request.json
        user_message = data.get('text', '')
        greeting_response = handle_greetings_and_introductions(user_message)
        if greeting_response: return jsonify({'response': greeting_response})

        files_data = data.get('filesData', [])
        request_mode = data.get('mode')
        ai_response = None
        
        # ==========================================================
        # ZAP VULNERABILITY SCAN WITH NVD API & MEMORY/TIMEOUT FIX
        # ==========================================================
        if request_mode == 'vuln_scan':
            target_url = user_message.strip()
            if not target_url.startswith(('http://', 'https://')): target_url = 'https://' + target_url
            if not urlparse(target_url).netloc:
                return jsonify({'response': "Invalid URL provided. Please provide a valid target like 'example.com'."})

            print(f"🔍 Starting ZAP Quick Scan for {target_url}...")
            report_path = "/tmp/zap_report.json"
            
            # MEMORY FIX: Restrict ZAP JVM to 300MB to prevent SIGKILL on Render Free Tier
            custom_env = os.environ.copy()
            custom_env["JAVA_OPTS"] = "-Xmx300m"
            
            zap_command = ["/opt/zap/zap.sh", "-cmd", "-quickurl", target_url, "-quickout", report_path, "-quickprogress"]

            try:
                # TIMEOUT FIX: Render limits to 100s. We set timeout to 85s to catch it gracefully.
                process = subprocess.run(zap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=85, env=custom_env)
                
                if os.path.exists(report_path):
                    with open(report_path, 'r') as f: report_data = json.load(f)
                    alerts = report_data.get('site', [])[0].get('alerts', []) if report_data.get('site') else []
                    
                    if not alerts:
                        ai_response = f"✅ **ZAP Scan Complete!** No obvious vulnerabilities were found for `{target_url}` within the time limit."
                    else:
                        ai_response = f"⚠️ **ZAP Scan Complete for `{target_url}`!**\n\n### Found the following vulnerabilities:\n\n"
                        
                        nvd_calls = 0 # Limit to 3 to prevent Render timeout
                        for alert in alerts:
                            riskdesc = alert.get('riskdesc', 'Unknown Risk')
                            name = alert.get('name', 'Unknown Vulnerability')
                            cweid = alert.get('cweid', '-1')
                            
                            ai_response += f"#### 🔴 {name}\n"
                            ai_response += f"**Risk:** {riskdesc}\n"
                            
                            # Provide CWE link if available
                            if str(cweid) != '-1' and str(cweid) != '':
                                ai_response += f"**CWE:** [CWE-{cweid}](https://cwe.mitre.org/data/definitions/{cweid}.html)\n"
                            
                            # NEW FEATURE: NVD Database lookup for CVE
                            if nvd_calls < 3 and ("High" in riskdesc or "Medium" in riskdesc):
                                cve_id = get_cve_from_nvd(name)
                                if cve_id:
                                    ai_response += f"**NVD Reference (CVE):** [{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})\n"
                                nvd_calls += 1
                                
                            ai_response += "\n---\n"
                            
                    os.remove(report_path)
                else:
                    ai_response = f"❌ **Scan Failed:** ZAP did not generate a report. It may have run out of memory internally.\n\nError: {process.stderr[-200:]}"
                return jsonify({'response': ai_response})

            except subprocess.TimeoutExpired:
                return jsonify({'response': f"⏱️ **Scan Timeout:** The vulnerability scan for `{target_url}` took longer than 85 seconds. To prevent the server from crashing, the scan was safely aborted."})
            except Exception as e:
                return jsonify({'response': f"❌ **Error running ZAP:** {str(e)}"})
                
        # --- Sofia AI Identity ---
        FULL_IDENTITY = "I am Sofia AI, a Security-Focused Multimodal Assistant. I specialize in security analysis. I NEVER say 'I'm a large language model'."
        
        # Process files
        extracted_texts = []
        is_code_file, code_file_content, code_file_name = False, None, ""
        image_files, has_images, has_documents = [], False, False
        code_extensions = ['.py', '.js', '.java', '.c', '.cpp', '.h', '.html', '.css', '.json', '.md', '.sh', '.rb', '.go', '.php']
        
        for file_item in files_data:
            file_data, file_type, file_name = file_item.get('data'), file_item.get('type', ''), file_item.get('name', '')
            if not file_data: continue
            
            if any(file_name.lower().endswith(ext) for ext in code_extensions):
                is_code_file, code_file_name = True, file_name
                try: code_file_content = base64.b64decode(file_data).decode('utf-8', errors='ignore')
                except Exception: code_file_content = "Error reading code file."
            elif file_type.startswith('image/'):
                image_files.append({'bytes': base64.b64decode(file_data), 'filename': file_name})
                has_images = True
            elif 'pdf' in file_type:
                extracted_texts.append(f"PDF Content from '{file_name}':\n{extract_text_from_pdf(base64.b64decode(file_data))[:5000]}")
                has_documents = True
            elif 'text/' in file_type:
                extracted_texts.append(f"Text Content from '{file_name}':\n{base64.b64decode(file_data).decode('utf-8', errors='ignore')[:5000]}")
        
        combined_text = user_message
        if extracted_texts: combined_text += "\n\n--- File Contents ---\n" + "\n\n".join(extracted_texts)
        if is_code_file and code_file_content: combined_text = f"{user_message}\n\nCode to analyze from '{code_file_name}':\n\n{code_file_content}"
        
        # --- Standard AI processing (Gemini -> Groq Fallback) ---
        gemini_failed, use_groq_fallback, gemini_response, groq_response = False, False, None, None
        
        if image_files:
            try:
                model = genai.GenerativeModel("gemini-2.5-flash-lite")
                parts = [f"I am Sofia AI. Analyze these images for security-related content.\n\nUser request: {combined_text}"]
                for img in image_files: parts.append(Image.open(io.BytesIO(img['bytes'])))
                gemini_response = model.generate_content(parts).text
            except Exception as e:
                gemini_failed, use_groq_fallback = True, True
                
        elif not gemini_failed and combined_text.strip():
            try:
                model = genai.GenerativeModel("gemini-2.5-flash-lite")
                gemini_response = model.generate_content([{'role': 'user', 'parts': [FULL_IDENTITY]}, {'role': 'user', 'parts': [combined_text]}]).text
            except Exception as e:
                gemini_failed, use_groq_fallback = True, True
                
        if use_groq_fallback and GROQ_API_KEY:
            groq_history = [{"role": "system", "content": FULL_IDENTITY}, {"role": "user", "content": combined_text}]
            groq_response = call_api("https://api.groq.com/openai/v1/chat/completions", {"Authorization": f"Bearer {GROQ_API_KEY}"}, {"model": "llama-3.1-8b-instant", "messages": groq_history}, "Groq")
            if groq_response: groq_response = f"⚠️ *Note: Using Groq API as Gemini was unavailable*\n\n{groq_response}"

        if gemini_response: ai_response = gemini_response
        elif groq_response: ai_response = groq_response
        else: ai_response = "Sorry, I'm having trouble generating a response. Please try again."

        return jsonify({'response': ai_response})
        
    except Exception as e:
        return jsonify({'response': f"Sorry, an internal error occurred: {str(e)}"})

# (CRUD Routes for Chats, Library, Feedback omitted for brevity, but they remain identical)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
