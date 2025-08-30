# CyberGuardian AI - Complete Backend System
# File: main.py

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
import re
import json
import base64
import hashlib
import secrets
import sqlite3
from textblob import TextBlob
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import pickle
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberguardian.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Initialize encryption
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Logging setup
logging.basicConfig(
    filename='cyberguardian.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# ===========================================
# DATABASE MODELS
# ===========================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    is_anonymous = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    
class ThreatAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    content_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash for privacy
    encrypted_content = db.Column(db.Text, nullable=False)  # Encrypted original content
    threat_type = db.Column(db.String(50), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    is_scam = db.Column(db.Boolean, nullable=False)
    analysis_result = db.Column(db.Text, nullable=False)  # JSON string
    source_type = db.Column(db.String(20), nullable=False)  # text, image, url, whatsapp
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    complaint_id = db.Column(db.String(20), unique=True, nullable=False)
    incident_type = db.Column(db.String(50), nullable=False)
    encrypted_description = db.Column(db.Text, nullable=False)
    encrypted_suspect_details = db.Column(db.Text, nullable=True)
    financial_loss = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='submitted')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    session_id = db.Column(db.String(36), unique=True, nullable=False)
    chat_type = db.Column(db.String(20), nullable=False)  # support, family_voice, crisis
    encrypted_messages = db.Column(db.Text, nullable=False)  # JSON array of messages
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class WhatsAppAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    chat_hash = db.Column(db.String(64), unique=True, nullable=False)
    encrypted_chat_data = db.Column(db.Text, nullable=False)
    participants_count = db.Column(db.Integer, nullable=False)
    message_count = db.Column(db.Integer, nullable=False)
    threat_indicators = db.Column(db.Text, nullable=False)  # JSON array
    family_voice_detected = db.Column(db.Boolean, default=False)
    sextortion_risk = db.Column(db.Integer, default=0)
    overall_risk = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ===========================================
# SECURITY & ENCRYPTION UTILITIES
# ===========================================

def encrypt_data(data):
    """Encrypt sensitive data"""
    if isinstance(data, str):
        data = data.encode()
    return cipher_suite.encrypt(data).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def hash_content(content):
    """Create SHA-256 hash of content for privacy"""
    return hashlib.sha256(content.encode()).hexdigest()

def generate_complaint_id():
    """Generate unique complaint ID"""
    return f"CG{datetime.now().strftime('%Y%m%d')}{secrets.token_hex(4).upper()}"

def generate_session_id():
    """Generate unique session ID"""
    return secrets.token_urlsafe(32)

# ===========================================
# AI-POWERED THREAT DETECTION
# ===========================================

class AdvancedThreatDetector:
    def __init__(self):
        self.scam_patterns = {
            'upi_fraud': [
                r'(?:upi|payment|transfer).*(?:urgent|immediate|asap|now)',
                r'(?:send|transfer).*(?:money|amount|payment).*(?:urgent|now)',
                r'(?:otp|pin|cvv).*(?:share|send|tell|give)',
                r'(?:account|bank).*(?:verify|update|suspend|block)',
                r'(?:transaction|payment).*(?:failed|pending|hold)',
                r'(?:refund|cashback).*(?:claim|get|receive)',
            ],
            'romance_scam': [
                r'(?:love|darling|sweetheart|dear).*(?:money|help|emergency)',
                r'(?:meet|come|visit).*(?:country|visa|ticket|travel)',
                r'(?:military|soldier|doctor|engineer).*(?:deployed|overseas|abroad)',
                r'(?:investment|business|gold|diamond).*(?:opportunity|profit|rich)',
                r'(?:family|mother|father).*(?:sick|hospital|operation|emergency)',
                r'(?:trust|believe|faith).*(?:money|financial|help)',
            ],
            'sextortion': [
                r'(?:video|photos|images|pictures).*(?:leak|share|publish|post)',
                r'(?:intimate|private|personal|naked).*(?:content|pictures|video)',
                r'(?:money|payment|bitcoin).*(?:delete|remove|not share)',
                r'(?:family|friends|contacts).*(?:send|show|share)',
                r'(?:embarrass|shame|ruin|destroy).*(?:reputation|life|career)',
                r'(?:social media|facebook|instagram|whatsapp).*(?:post|share)',
            ],
            'job_fraud': [
                r'(?:job|work|employment|opportunity).*(?:home|online).*(?:easy|simple)',
                r'(?:earn|make|get).*(?:\₹|\$|money).*(?:daily|weekly|monthly)',
                r'(?:no|without).*(?:experience|skills|qualification)',
                r'(?:registration|joining|processing).*(?:fee|payment|charges)',
                r'(?:part.time|parttime).*(?:work|job).*(?:mobile|phone|whatsapp)',
                r'(?:data entry|copy paste|survey|form filling).*(?:money|payment)',
            ],
            'loan_fraud': [
                r'(?:loan|credit|finance).*(?:approved|sanctioned|granted).*(?:instantly|immediately)',
                r'(?:no|without).*(?:documents|paperwork|verification|guarantee)',
                r'(?:processing|admin|handling).*(?:fee|charges|cost)',
                r'(?:aadhar|pan|bank).*(?:number|details|account).*(?:required|needed)',
                r'(?:cibil|credit score|defaulter).*(?:no problem|not required)',
                r'(?:collateral|security|guarantee).*(?:not required|no need)',
            ],
            'impersonation': [
                r'(?:bank|police|customs|officer|authority).*(?:account|case|issue|problem)',
                r'(?:suspended|blocked|frozen|locked).*(?:account|card|service)',
                r'(?:immediate|urgent|within).*(?:action|response|reply).*(?:required|needed)',
                r'(?:legal|court|fir|case).*(?:action|notice|warrant)',
                r'(?:rbi|sebi|income tax|customs).*(?:notice|penalty|fine)',
                r'(?:kyc|verification|update).*(?:mandatory|compulsory|required)',
            ],
            'family_impersonation': [
                r'(?:mom|mother|dad|father|mama|papa|mummy|daddy)',
                r'(?:son|daughter|beta|beti|child)',
                r'(?:emergency|accident|hospital|police station)',
                r'(?:urgent|immediately|right now|asap)',
                r'(?:money|cash|payment|transfer)',
                r'(?:new number|changed number|lost phone)',
            ]
        }
        
        self.family_voice_indicators = [
            r'(?:mom|mother|dad|father|mama|papa|mummy|daddy|maa|baba)',
            r'(?:beta|beti|son|daughter|child|bachcha)',
            r'(?:urgent|emergency|help|problem|trouble)',
            r'(?:money|cash|send|transfer|need)',
            r'(?:accident|hospital|police|jail|custody)',
            r'(?:new phone|lost phone|broken phone|different number)',
        ]
        
        self.sextortion_indicators = [
            r'(?:photos|pictures|images|video|clip)',
            r'(?:private|intimate|personal|naked|nude)',
            r'(?:share|post|send|publish|leak|spread)',
            r'(?:money|payment|bitcoin|paytm|googlepay)',
            r'(?:delete|remove|not share|keep secret)',
            r'(?:family|friends|social media|facebook|whatsapp)',
        ]

    def analyze_whatsapp_conversation(self, chat_data):
        """Analyze WhatsApp conversation for threats"""
        messages = chat_data.get('messages', [])
        participants = chat_data.get('participants', [])
        
        # Initialize analysis results
        threat_indicators = []
        family_voice_score = 0
        sextortion_score = 0
        overall_risk_score = 0
        
        # Analyze each message
        for msg in messages:
            content = msg.get('content', '').lower()
            sender = msg.get('sender', '')
            timestamp = msg.get('timestamp', '')
            
            # Check for family voice impersonation
            family_matches = 0
            for pattern in self.family_voice_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    family_matches += 1
                    family_voice_score += 10
            
            if family_matches >= 3:  # High confidence family impersonation
                threat_indicators.append({
                    'type': 'family_voice_impersonation',
                    'confidence': min(100, family_matches * 20),
                    'message': content[:100] + '...',
                    'sender': sender,
                    'timestamp': timestamp
                })
            
            # Check for sextortion
            sextortion_matches = 0
            for pattern in self.sextortion_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    sextortion_matches += 1
                    sextortion_score += 15
            
            if sextortion_matches >= 2:  # High confidence sextortion
                threat_indicators.append({
                    'type': 'sextortion',
                    'confidence': min(100, sextortion_matches * 25),
                    'message': content[:50] + '...',  # Shorter excerpt for privacy
                    'sender': sender,
                    'timestamp': timestamp
                })
            
            # Check for other scam types
            for scam_type, patterns in self.scam_patterns.items():
                matches = sum(1 for pattern in patterns if re.search(pattern, content, re.IGNORECASE))
                if matches >= 2:
                    overall_risk_score += matches * 10
                    threat_indicators.append({
                        'type': scam_type,
                        'confidence': min(100, matches * 20),
                        'message': content[:100] + '...',
                        'sender': sender,
                        'timestamp': timestamp
                    })
        
        # Determine overall risk level
        total_score = family_voice_score + sextortion_score + overall_risk_score
        if total_score >= 80:
            risk_level = 'HIGH'
        elif total_score >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'threat_indicators': threat_indicators,
            'family_voice_detected': family_voice_score >= 30,
            'family_voice_score': family_voice_score,
            'sextortion_risk': min(100, sextortion_score),
            'overall_risk_score': min(100, total_score),
            'risk_level': risk_level,
            'message_count': len(messages),
            'participants_count': len(participants),
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

    def analyze_text(self, text):
        """Enhanced text analysis with ML"""
        # Existing pattern-based analysis
        detected_scams = []
        risk_score = 0
        risk_reasons = []
        
        # Check each pattern category
        for scam_type, patterns in self.scam_patterns.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches += 1
            
            if matches >= 2:
                detected_scams.append(scam_type)
                risk_score += matches * 15
                risk_reasons.append(f"{scam_type.replace('_', ' ').title()} indicators")
        
        # Additional risk factors
        risk_factors = [
            {'pattern': r'urgent|asap|immediate|now|today|quickly', 'weight': 10, 'desc': 'Urgency pressure'},
            {'pattern': r'money|payment|transfer|send|pay|cash', 'weight': 15, 'desc': 'Financial request'},
            {'pattern': r'click|link|download|install|visit', 'weight': 8, 'desc': 'Suspicious links'},
            {'pattern': r'otp|pin|password|cvv|bank details', 'weight': 25, 'desc': 'Sensitive info request'},
            {'pattern': r'whatsapp|telegram|call me|new number', 'weight': 5, 'desc': 'Platform switching'},
            {'pattern': r'secret|private|confidential|dont tell', 'weight': 12, 'desc': 'Secrecy request'},
            {'pattern': r'limited time|expire|offer ends|act fast', 'weight': 8, 'desc': 'Time pressure'},
        ]
        
        for factor in risk_factors:
            matches = re.findall(factor['pattern'], text, re.IGNORECASE)
            if matches:
                risk_score += factor['weight'] * min(len(matches), 3)
                risk_reasons.append(factor['desc'])
        
        # Sentiment analysis
        blob = TextBlob(text)
        sentiment_score = blob.sentiment.polarity
        
        if sentiment_score < -0.3:  # Very negative sentiment
            risk_score += 10
            risk_reasons.append('Negative/threatening tone')
        
        # Determine risk level and recommendations
        if risk_score >= 60 or len(detected_scams) > 0:
            risk_level = 'HIGH RISK - POTENTIAL SCAM'
            is_scam = True
            recommendations = [
                '❌ Do NOT respond or engage with this message',
                '❌ Do NOT click any links or download attachments',
                '❌ Do NOT share personal or financial information',
                '📞 Report to cyber crime helpline: 1930',
                '🚫 Block the sender immediately',
                '💬 Talk to CyberGuardian AI support if you need help'
            ]
        elif risk_score >= 30:
            risk_level = 'MEDIUM RISK - BE CAUTIOUS'
            is_scam = False
            recommendations = [
                '✅ Verify sender identity through official channels',
                '✅ Cross-check information with official sources',
                '❌ Avoid sharing sensitive information',
                '🤔 Take time to think before responding',
                '💭 Discuss with trusted friends or family'
            ]
        else:
            risk_level = 'LOW RISK - APPEARS SAFE'
            is_scam = False
            recommendations = [
                '✅ Message appears legitimate',
                '💡 Still verify if you have any doubts',
                '📚 Stay informed about new scam types',
                '🛡️ Keep CyberGuardian AI bookmarked for future checks'
            ]
        
        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 100),
            'is_scam': is_scam,
            'detected_scams': detected_scams,
            'risk_reasons': list(set(risk_reasons)),
            'recommendations': recommendations,
            'sentiment_score': sentiment_score,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

# Initialize threat detector
threat_detector = AdvancedThreatDetector()

# ===========================================
# AI VICTIM SUPPORT CHATBOT
# ===========================================

class VictimSupportBot:
    def __init__(self):
        self.crisis_keywords = [
            'scared', 'afraid', 'terrified', 'panicked', 'help', 'emergency',
            'suicide', 'kill myself', 'end it all', 'cant take it',
            'blackmail', 'threatening', 'expose', 'leak', 'share photos'
        ]
        
        self.support_responses = {
            'initial_contact': [
                "🤗 Hello, I'm here to help you. You're not alone in this situation.",
                "💙 I understand you might be feeling scared or confused right now. That's completely normal.",
                "🛡️ First, know that you are SAFE here. Everything you tell me is confidential.",
                "📝 Can you tell me briefly what's happening? I'm here to listen and help."
            ],
            'sextortion_support': [
                "😌 I understand this is an extremely difficult situation. Please know that this is NOT your fault.",
                "🚫 The most important thing: DO NOT send any money or more content to the scammer.",
                "📱 Do NOT delete any evidence - screenshots, messages, photos. We'll need these for reporting.",
                "👮 This is a crime, and you are the victim. The person threatening you is breaking the law.",
                "💪 You are braver than you think for reaching out. We can get through this together."
            ],
            'family_impersonation': [
                "📞 First, try to contact your family member directly through their known phone number.",
                "🔍 Ask specific questions only your real family member would know the answer to.",
                "⏰ Real emergencies don't usually come with urgent payment demands.",
                "🚨 If this is truly urgent, your family would call you directly or involve authorities.",
                "💡 Scammers often create fake emergencies to make you act without thinking."
            ],
            'emotional_support': [
                "🫂 What you're feeling right now - fear, shame, confusion - these are normal reactions.",
                "🌅 This situation is temporary. With the right steps, we can resolve this.",
                "👥 Many people face similar situations. You're not the first, and help is available.",
                "💝 Your worth as a person is not defined by this situation.",
                "🌱 Taking the step to reach out for help shows incredible strength."
            ],
            'practical_steps': [
                "📋 Let's make a plan together. We'll take this step by step.",
                "🔒 First priority: Secure your accounts and don't send anything more.",
                "📞 Second: Report this to cyber crime helpline 1930 (they handle this daily).",
                "👨‍👩‍👧‍👦 Consider telling a trusted friend or family member - they care about you.",
                "📄 We can help you generate a report and complaint if you're ready."
            ]
        }
    
    def detect_crisis(self, message):
        """Detect if user is in crisis"""
        message_lower = message.lower()
        crisis_score = sum(1 for keyword in self.crisis_keywords if keyword in message_lower)
        return crisis_score >= 2
    
    def get_response(self, message, session_context):
        """Generate appropriate support response"""
        message_lower = message.lower()
        
        # Check for crisis indicators
        is_crisis = self.detect_crisis(message)
        
        if is_crisis:
            response = {
                'message': "🚨 I can see you're in distress. Please know that help is available RIGHT NOW.",
                'crisis_resources': [
                    "📞 National Suicide Prevention: 9152987821 (AASRA)",
                    "📞 Mental Health Helpline: 9820466726 (iCall)",
                    "📞 Cyber Crime Helpline: 1930",
                    "🚨 Emergency Services: 112"
                ],
                'immediate_actions': [
                    "Take deep breaths. You are safe right now.",
                    "If you're thinking of self-harm, please call a crisis hotline immediately.",
                    "Remember: This situation is temporary and can be resolved.",
                    "You are not alone. Professional help is available."
                ],
                'is_crisis': True
            }
        else:
            # Determine response type based on context
            if 'sextortion' in session_context.get('threat_type', ''):
                responses = self.support_responses['sextortion_support']
            elif 'family' in session_context.get('threat_type', ''):
                responses = self.support_responses['family_impersonation']
            elif session_context.get('message_count', 0) == 0:
                responses = self.support_responses['initial_contact']
            else:
                responses = self.support_responses['practical_steps']
            
            response = {
                'message': responses[0],  # Primary response
                'additional_support': responses[1:3] if len(responses) > 1 else [],
                'suggested_actions': [
                    "📝 Document everything - take screenshots",
                    "🚫 Don't engage further with the scammer",
                    "📞 Consider reporting to authorities",
                    "💬 Keep talking to me - I'm here to help"
                ],
                'is_crisis': False
            }
        
        return response

# Initialize victim support bot
support_bot = VictimSupportBot()

# ===========================================
# API ROUTES
# ===========================================

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Check if user exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=bcrypt.generate_password_hash(data['password']).decode('utf-8'),
            phone=data.get('phone'),
            is_anonymous=data.get('is_anonymous', False)
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Generate access token
        access_token = create_access_token(identity=user.id)
        
        logging.info(f"New user registered: {user.username}")
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user_id': user.id
        }), 201
        
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        user = User.query.filter_by(username=data['username']).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, data['password']):
            # Update last active
            user.last_active = datetime.utcnow()
            db.session.commit()
            
            access_token = create_access_token(identity=user.id)
            
            logging.info(f"User logged in: {user.username}")
            
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'user_id': user.id
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/analyze/text', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json()
        text_content = data['text']
        
        # Get user ID if authenticated
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass  # Anonymous user
        
        # Analyze the text
        analysis_result = threat_detector.analyze_text(text_content)
        
        # Encrypt and store the analysis
        content_hash = hash_content(text_content)
        encrypted_content = encrypt_data(text_content)
        
        threat_analysis = ThreatAnalysis(
            user_id=user_id,
            content_hash=content_hash,
            encrypted_content=encrypted_content,
            threat_type=','.join(analysis_result['detected_scams']) if analysis_result['detected_scams'] else 'none',
            risk_score=analysis_result['risk_score'],
            is_scam=analysis_result['is_scam'],
            analysis_result=json.dumps(analysis_result),
            source_type='text'
        )
        
        db.session.add(threat_analysis)
        db.session.commit()
        
        logging.info(f"Text analysis completed - Risk: {analysis_result['risk_score']} - Scam: {analysis_result['is_scam']}")
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'analysis_id': threat_analysis.id
        }), 200
        
    except Exception as e:
        logging.error(f"Text analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed'}), 500

@app.route('/api/analyze/whatsapp', methods=['POST'])
def analyze_whatsapp():
    try:
        data = request.get_json()
        chat_data = data['chat_data']
        
        # Get user ID if authenticated
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass
        
        # Analyze WhatsApp conversation
        analysis_result = threat_detector.analyze_whatsapp_conversation(chat_data)
        
        # Create hash for the chat
        chat_content = json.dumps(chat_data, sort_keys=True)
        chat_hash = hash_content(chat_content)
        
        # Encrypt chat data
        encrypted_chat_data = encrypt_data(chat_content)
        
        # Store analysis
        whatsapp_analysis = WhatsAppAnalysis(
            user_id=user_id,
            chat_hash=chat_hash,
            encrypted_chat_data=encrypted_chat_data,
            participants_count=analysis_result['participants_count'],
            message_count=analysis_result['message_count'],
            threat_indicators=json.dumps(analysis_result['threat_indicators']),
            family_voice_detected=analysis_result['family_voice_detected'],
            sextortion_risk=analysis_result['sextortion_risk'],
            overall_risk=analysis_result['risk_level']
        )
        
        db.session.add(whatsapp_analysis)
        db.session.commit()
        
        logging.info(f"WhatsApp analysis completed - Risk: {analysis_result['risk_level']} - Family voice: {analysis_result['family_voice_detected']}")
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'analysis_id': whatsapp_analysis.id
        }), 200
        
    except Exception as e:
        logging.error(f"WhatsApp analysis error: {str(e)}")
        return jsonify({'error': 'WhatsApp analysis failed'}), 500

@app.route('/api/chat/support', methods=['POST'])
def chat_support():
    try:
        data = request.get_json()
        message = data['message']
        session_id = data.get('session_id')
        
        # Get user ID if authenticated
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass
        
        # Create new session if not provided
        if not session_id:
            session_id = generate_session_id()
            
            chat_session = ChatSession(
                user_id=user_id,
                session_id=session_id,
                chat_type='support',
                encrypted_messages=encrypt_data(json.dumps([]))
            )
            db.session.add(chat_session)
        else:
            chat_session = ChatSession.query.filter_by(session_id=session_id).first()
            if not chat_session:
                return jsonify({'error': 'Invalid session ID'}), 400
        
        # Get existing messages
        try:
            existing_messages = json.loads(decrypt_data(chat_session.encrypted_messages))
        except:
            existing_messages = []
        
        # Add user message
        user_message = {
            'sender': 'user',
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        existing_messages.append(user_message)
        
        # Generate bot response
        session_context = {
            'message_count': len(existing_messages),
            'threat_type': data.get('threat_type', ''),
            'user_emotions': data.get('emotions', [])
        }
        
        bot_response = support_bot.get_response(message, session_context)
        
        # Add bot response to messages
        bot_message = {
            'sender': 'bot',
            'message': bot_response['message'],
            'additional_support': bot_response.get('additional_support', []),
            'suggested_actions': bot_response.get('suggested_actions', []),
            'crisis_resources': bot_response.get('crisis_resources', []),
            'is_crisis': bot_response.get('is_crisis', False),
            'timestamp': datetime.utcnow().isoformat()
        }
        existing_messages.append(bot_message)
        
        # Update encrypted messages
        chat_session.encrypted_messages = encrypt_data(json.dumps(existing_messages))
        chat_session.updated_at = datetime.utcnow()
        db.session.commit()
        
        logging.info(f"Support chat response generated - Session: {session_id} - Crisis: {bot_response.get('is_crisis', False)}")
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'bot_response': bot_response,
            'message_count': len(existing_messages)
        }), 200
        
    except Exception as e:
        logging.error(f"Support chat error: {str(e)}")
        return jsonify({'error': 'Chat support failed'}), 500

@app.route('/api/complaint/create', methods=['POST'])
@jwt_required(optional=True)
def create_complaint():
    try:
        data = request.get_json()
        
        user_id = get_jwt_identity()
        
        # Generate unique complaint ID
        complaint_id = generate_complaint_id()
        
        # Encrypt sensitive data
        encrypted_description = encrypt_data(data['description'])
        encrypted_suspect_details = encrypt_data(data.get('suspect_details', ''))
        
        complaint = Complaint(
            user_id=user_id,
            complaint_id=complaint_id,
            incident_type=data['incident_type'],
            encrypted_description=encrypted_description,
            encrypted_suspect_details=encrypted_suspect_details,
            financial_loss=data.get('financial_loss', 0)
        )
        
        db.session.add(complaint)
        db.session.commit()
        
        # Generate FIR template
        fir_content = generate_fir_template(complaint, data)
        
        logging.info(f"Complaint created: {complaint_id}")
        
        return jsonify({
            'success': True,
            'complaint_id': complaint_id,
            'fir_template': fir_content,
            'message': 'Complaint registered successfully'
        }), 201
        
    except Exception as e:
        logging.error(f"Complaint creation error: {str(e)}")
        return jsonify({'error': 'Failed to create complaint'}), 500

@app.route('/api/complaint/status/<complaint_id>', methods=['GET'])
@jwt_required()
def get_complaint_status(complaint_id):
    try:
        user_id = get_jwt_identity()
        
        complaint = Complaint.query.filter_by(
            complaint_id=complaint_id,
            user_id=user_id
        ).first()
        
        if not complaint:
            return jsonify({'error': 'Complaint not found'}), 404
        
        return jsonify({
            'complaint_id': complaint.complaint_id,
            'incident_type': complaint.incident_type,
            'status': complaint.status,
            'created_at': complaint.created_at.isoformat(),
            'updated_at': complaint.updated_at.isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Get complaint status error: {str(e)}")
        return jsonify({'error': 'Failed to get complaint status'}), 500

@app.route('/api/stats/dashboard', methods=['GET'])
@jwt_required(optional=True)
def get_dashboard_stats():
    try:
        user_id = get_jwt_identity()
        
        # Global stats
        total_analyses = ThreatAnalysis.query.count()
        total_threats = ThreatAnalysis.query.filter_by(is_scam=True).count()
        total_complaints = Complaint.query.count()
        total_users = User.query.count()
        
        # User-specific stats if authenticated
        user_stats = {}
        if user_id:
            user_analyses = ThreatAnalysis.query.filter_by(user_id=user_id).count()
            user_threats = ThreatAnalysis.query.filter_by(user_id=user_id, is_scam=True).count()
            user_complaints = Complaint.query.filter_by(user_id=user_id).count()
            
            user_stats = {
                'user_analyses': user_analyses,
                'user_threats_detected': user_threats,
                'user_complaints': user_complaints,
                'user_protection_score': min(100, (user_analyses * 2) + (user_threats * 5))
            }
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_analyses = ThreatAnalysis.query.filter(
            ThreatAnalysis.created_at >= recent_cutoff
        ).count()
        
        recent_threats = ThreatAnalysis.query.filter(
            ThreatAnalysis.created_at >= recent_cutoff,
            ThreatAnalysis.is_scam == True
        ).count()
        
        return jsonify({
            'global_stats': {
                'total_analyses': total_analyses,
                'total_threats_detected': total_threats,
                'total_complaints': total_complaints,
                'total_users': total_users,
                'recent_analyses_24h': recent_analyses,
                'recent_threats_24h': recent_threats
            },
            'user_stats': user_stats,
            'protection_rate': round((total_threats / max(total_analyses, 1)) * 100, 2)
        }), 200
        
    except Exception as e:
        logging.error(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': 'Failed to get dashboard stats'}), 500

@app.route('/api/emergency/alert', methods=['POST'])
@jwt_required(optional=True)
def emergency_alert():
    try:
        data = request.get_json()
        alert_type = data['alert_type']
        
        user_id = get_jwt_identity()
        
        # Log emergency alert
        logging.warning(f"EMERGENCY ALERT - Type: {alert_type} - User: {user_id}")
        
        # Generate emergency response based on type
        emergency_responses = {
            'sextortion': {
                'immediate_actions': [
                    '🚫 STOP all communication with the scammer immediately',
                    '📱 Do NOT send any more photos, videos, or money',
                    '📷 Take screenshots of all conversations as evidence',
                    '🚨 Report to Cyber Crime Helpline: 1930 RIGHT NOW',
                    '💬 Talk to CyberGuardian AI support - you are not alone'
                ],
                'resources': [
                    {'name': 'Cyber Crime Helpline', 'number': '1930'},
                    {'name': 'Mental Health Support (AASRA)', 'number': '9152987821'},
                    {'name': 'Women Helpline', 'number': '181'},
                    {'name': 'Emergency Services', 'number': '112'}
                ]
            },
            'upi_fraud': {
                'immediate_actions': [
                    '🏦 Contact your bank immediately to block account/card',
                    '📞 Call bank customer care and report fraud',
                    '🚫 Do NOT share any more OTPs or bank details',
                    '📱 Change your UPI PIN immediately',
                    '🚨 Report to Cyber Crime: 1930 and local police',
                    '💳 Monitor all account transactions closely'
                ],
                'resources': [
                    {'name': 'Banking Fraud Helpline', 'number': '1930'},
                    {'name': 'State Bank Customer Care', 'number': '1800112211'},
                    {'name': 'HDFC Customer Care', 'number': '18002703333'},
                    {'name': 'ICICI Customer Care', 'number': '18001034488'}
                ]
            },
            'family_emergency': {
                'immediate_actions': [
                    '📞 Call your family member directly on their known number',
                    '❓ Ask specific questions only they would know',
                    '🏥 If claiming hospital emergency, call the hospital directly',
                    '👮 Real emergencies involve police/hospitals calling you',
                    '💰 NEVER send money based on urgent requests',
                    '🤝 Consult other family members before acting'
                ],
                'resources': [
                    {'name': 'Emergency Services', 'number': '112'},
                    {'name': 'Cyber Crime Helpline', 'number': '1930'},
                    {'name': 'Local Police', 'number': '100'}
                ]
            }
        }
        
        response = emergency_responses.get(alert_type, {
            'immediate_actions': [
                '🚨 You are in an emergency situation',
                '📞 Contact Cyber Crime Helpline: 1930',
                '🚫 Stop all communication with suspicious parties',
                '📷 Document everything as evidence',
                '💬 Seek immediate support from trusted contacts'
            ],
            'resources': [
                {'name': 'Cyber Crime Helpline', 'number': '1930'},
                {'name': 'Emergency Services', 'number': '112'}
            ]
        })
        
        return jsonify({
            'success': True,
            'alert_type': alert_type,
            'emergency_response': response,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Emergency alert error: {str(e)}")
        return jsonify({'error': 'Emergency alert failed'}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data['url']
        
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass
        
        # Enhanced URL analysis
        analysis_result = analyze_url_security(url)
        
        # Store analysis
        content_hash = hash_content(url)
        encrypted_content = encrypt_data(url)
        
        threat_analysis = ThreatAnalysis(
            user_id=user_id,
            content_hash=content_hash,
            encrypted_content=encrypted_content,
            threat_type='url_analysis',
            risk_score=analysis_result['risk_score'],
            is_scam=analysis_result['is_malicious'],
            analysis_result=json.dumps(analysis_result),
            source_type='url'
        )
        
        db.session.add(threat_analysis)
        db.session.commit()
        
        logging.info(f"URL analysis completed - URL: {url[:50]}... - Risk: {analysis_result['risk_score']}")
        
        return jsonify({
            'success': True,
            'analysis': analysis_result
        }), 200
        
    except Exception as e:
        logging.error(f"URL analysis error: {str(e)}")
        return jsonify({'error': 'URL analysis failed'}), 500

# ===========================================
# UTILITY FUNCTIONS
# ===========================================

def generate_fir_template(complaint, data):
    """Generate FIR template"""
    fir_template = f"""
FIRST INFORMATION REPORT (FIR)
CYBER CRIME COMPLAINT

Date: {datetime.now().strftime('%d/%m/%Y')}
Time: {datetime.now().strftime('%H:%M:%S')}
FIR No: {complaint.complaint_id}

COMPLAINANT DETAILS:
Name: {data.get('complainant_name', 'Anonymous')}
Contact: {data.get('contact_number', 'Not provided')}
Email: {data.get('email_address', 'Not provided')}
Address: {data.get('address', 'Not provided')}

INCIDENT DETAILS:
Type of Cyber Crime: {complaint.incident_type.replace('_', ' ').upper()}
Date of Incident: {data.get('incident_date', datetime.now().strftime('%d/%m/%Y'))}
Time of Incident: {data.get('incident_time', 'Not specified')}

DESCRIPTION OF INCIDENT:
{decrypt_data(complaint.encrypted_description) if complaint.encrypted_description else 'No description provided'}

FINANCIAL LOSS:
Amount Lost: ₹{complaint.financial_loss or 0}
Transaction Details: {data.get('transaction_details', 'Not provided')}

SUSPECT INFORMATION:
{decrypt_data(complaint.encrypted_suspect_details) if complaint.encrypted_suspect_details else 'No suspect details provided'}

EVIDENCE:
- Screenshots/Messages: {data.get('evidence_screenshots', 'Not provided')}
- Bank Statements: {data.get('evidence_statements', 'Not provided')}
- Other Evidence: {data.get('evidence_other', 'Not provided')}

REQUESTED ACTION:
1. Investigation of the reported cyber crime
2. Recovery of financial losses (if applicable)
3. Legal action against perpetrators as per IT Act 2000 and IPC
4. Prevention of further fraudulent activities

DECLARATION:
I hereby declare that the information provided above is true and correct to the best of my knowledge and belief.

Complainant Signature: ________________
Date: {datetime.now().strftime('%d/%m/%Y')}

Generated by: CyberGuardian AI System
Report ID: {complaint.complaint_id}
Generated on: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

NEXT STEPS:
1. Submit this FIR to your nearest cyber crime police station
2. Visit https://cybercrime.gov.in for online complaint filing
3. Contact National Cyber Crime Helpline: 1930
4. Keep this document and all evidence safely
5. Follow up with investigating officer regularly

IMPORTANT CONTACT NUMBERS:
- Cyber Crime Helpline: 1930
- Emergency Services: 112
- Women Helpline: 181
- Mental Health Support: 9152987821 (AASRA)
"""
    return fir_template

def analyze_url_security(url):
    """Enhanced URL security analysis"""
    risk_score = 0
    risk_factors = []
    
    # Basic URL structure analysis
    suspicious_patterns = [
        (r'bit\.ly|tinyurl|short\.link|t\.co', 20, 'URL shortener detected'),
        (r'\d+\.\d+\.\d+\.\d+', 25, 'IP address instead of domain'),
        (r'[a-z]+-[a-z]+-[a-z]+\.com', 15, 'Randomly generated domain pattern'),
        (r'secure.*\d+|verify.*\d+|update.*\d+', 20, 'Fake security site pattern'),
        (r'(bank|paypal|amazon|google|microsoft).*\d+', 25, 'Brand impersonation attempt'),
        (r'[0-9]{8,}', 10, 'Suspicious number sequences'),
        (r'\.tk$|\.ml$|\.ga$|\.cf, 15, 'Free domain extension'),
    ]
    
    for pattern, weight, description in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            risk_score += weight
            risk_factors.append(description)
    
    # Protocol check
    if not url.startswith('https://'):
        risk_score += 15
        risk_factors.append('Not using secure HTTPS protocol')
    
    # Domain reputation check (simulated)
    known_malicious_indicators = ['phish', 'scam', 'fake', 'malware', 'virus']
    for indicator in known_malicious_indicators:
        if indicator in url.lower():
            risk_score += 30
            risk_factors.append(f'Contains suspicious keyword: {indicator}')
    
    # Length analysis
    if len(url) > 100:
        risk_score += 10
        risk_factors.append('Unusually long URL')
    
    # Special character analysis
    special_chars = url.count('-') + url.count('_') + url.count('.')
    if special_chars > 10:
        risk_score += 8
        risk_factors.append('Excessive special characters')
    
    # Determine threat level
    if risk_score >= 50:
        threat_level = 'HIGH RISK - AVOID'
        is_malicious = True
        recommendations = [
            '❌ DO NOT visit this website',
            '❌ DO NOT enter any personal information',
            '🚨 Report this URL as malicious',
            '🛡️ Use official websites only',
            '📞 If received via message, report to 1930'
        ]
    elif risk_score >= 25:
        threat_level = 'MEDIUM RISK - CAUTION'
        is_malicious = False
        recommendations = [
            '⚠️ Proceed with extreme caution',
            '🔍 Verify website legitimacy independently',
            '❌ Avoid entering sensitive information',
            '📱 Cross-check with official sources',
            '🤔 Consider using alternative official sites'
        ]
    else:
        threat_level = 'LOW RISK - APPEARS SAFE'
        is_malicious = False
        recommendations = [
            '✅ URL appears legitimate',
            '🔒 Still verify SSL certificate',
            '💡 Check for official domain indicators',
            '🛡️ Stay alert for any suspicious behavior'
        ]
    
    return {
        'url': url,
        'threat_level': threat_level,
        'risk_score': min(risk_score, 100),
        'is_malicious': is_malicious,
        'risk_factors': risk_factors,
        'recommendations': recommendations,
        'analysis_timestamp': datetime.utcnow().isoformat()
    }

# ===========================================
# DATABASE INITIALIZATION
# ===========================================

@app.before_first_request
def create_tables():
    """Create database tables"""
    db.create_all()
    logging.info("Database tables created successfully")

# ===========================================
# ERROR HANDLERS
# ===========================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized access'}), 401

# ===========================================
# ADDITIONAL SECURITY FEATURES
# ===========================================

@app.route('/api/security/encrypt', methods=['POST'])
@jwt_required()
def encrypt_user_data():
    """Allow users to encrypt their sensitive data"""
    try:
        data = request.get_json()
        sensitive_data = data['data']
        
        encrypted_data = encrypt_data(sensitive_data)
        data_hash = hash_content(sensitive_data)
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_data,
            'data_hash': data_hash,
            'message': 'Data encrypted successfully'
        }), 200
        
    except Exception as e:
        logging.error(f"Data encryption error: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/api/security/report-phishing', methods=['POST'])
def report_phishing():
    """Report phishing attempts"""
    try:
        data = request.get_json()
        
        phishing_report = {
            'url': data.get('url', ''),
            'message': data.get('message', ''),
            'source': data.get('source', ''),
            'reporter_id': get_jwt_identity() if request.headers.get('Authorization') else None,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # In production, this would go to a security team database
        logging.warning(f"PHISHING REPORT: {json.dumps(phishing_report)}")
        
        return jsonify({
            'success': True,
            'message': 'Phishing attempt reported successfully',
            'report_id': f"PHI{datetime.now().strftime('%Y%m%d')}{secrets.token_hex(4).upper()}"
        }), 200
        
    except Exception as e:
        logging.error(f"Phishing report error: {str(e)}")
        return jsonify({'error': 'Failed to report phishing'}), 500

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        db.create_all()
        logging.info("CyberGuardian AI Backend started successfully")
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)