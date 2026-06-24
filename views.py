from flask import Blueprint, render_template, request, jsonify, send_file
import subprocess
import re
import requests
import hashlib
import pymysql
import google.generativeai as genai
import json
import pandas as pd
import numpy as np
import os
import urllib.parse
from urllib.parse import urlparse
import csv
import PyPDF2
import io
import time
try:
    import fitz  # PyMuPDF
    _PYMUPDF_AVAILABLE = hasattr(fitz, "open")
except Exception:
    fitz = None
    _PYMUPDF_AVAILABLE = False
import sqlite3

views = Blueprint("views", __name__)

# Configure Google Gemini API
genai.configure(api_key="AIzaSyC6nd6hHg9vbAYRnmx_Kj6_uOIDaCleUI4")
model = genai.GenerativeModel('gemini-2.0-flash')

# Load phishing dataset for URL analysis
phishing_data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'training resource', 'Phishing_Legitimate_full.csv')
try:
    phishing_df = pd.read_csv(phishing_data_path)
    print(f"Loaded phishing dataset with {len(phishing_df)} records")
except Exception as e:
    print(f"Error loading phishing dataset: {str(e)}")
    phishing_df = None

# Load and extract content from PDF resources
def extract_pdf_text(pdf_path):
    """Extract text from a PDF using PyMuPDF if available, otherwise PyPDF2.

    This gracefully handles environments where an unrelated 'fitz' package is installed
    or PyMuPDF is missing, avoiding hard crashes at import-time.
    """
    # Preferred: PyMuPDF
    if _PYMUPDF_AVAILABLE:
        try:
            text = ""
            with fitz.open(pdf_path) as doc:
                for page in doc:
                    text += page.get_text()
            return text
        except Exception as e:
            print(f"PyMuPDF failed for {pdf_path}: {str(e)}. Falling back to PyPDF2.")

    # Fallback: PyPDF2
    try:
        reader = PyPDF2.PdfReader(pdf_path)
        pages_text = []
        for page in reader.pages:
            pages_text.append(page.extract_text() or "")
        return "\n".join(pages_text)
    except Exception as e:
        print(f"Error extracting text from PDF {pdf_path} with PyPDF2: {str(e)}")
        return ""

# Extract content from NIST Cybersecurity Framework PDF
nist_pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'training resource', 'NIST.CSWP.04162018.pdf')
try:
    nist_content = extract_pdf_text(nist_pdf_path)
    print(f"Loaded NIST Cybersecurity Framework PDF with {len(nist_content)} characters")
    # Create a summary of key topics in the NIST framework
    nist_topics = [
        "Identify - Asset Management, Business Environment, Governance, Risk Assessment, Risk Management Strategy",
        "Protect - Identity Management, Access Control, Awareness and Training, Data Security, Maintenance",
        "Detect - Anomalies and Events, Security Continuous Monitoring, Detection Processes",
        "Respond - Response Planning, Communications, Analysis, Mitigation, Improvements",
        "Recover - Recovery Planning, Improvements, Communications"
    ]
    nist_summary = "\n".join(nist_topics)
except Exception as e:
    print(f"Error loading NIST PDF: {str(e)}")
    nist_content = ""
    nist_summary = ""

# Extract content from OWASP Testing Guide PDF
owasp_pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'training resource', 'OWASP_Testing_Guide_v4.pdf')
try:
    owasp_content = extract_pdf_text(owasp_pdf_path)
    print(f"Loaded OWASP Testing Guide PDF with {len(owasp_content)} characters")
    # Create a summary of key topics in the OWASP guide
    owasp_topics = [
        "Information Gathering - Web server fingerprinting, application platform identification",
        "Configuration Management - Infrastructure configuration, application configuration",
        "Identity Management - User registration, authentication, session management",
        "Authorization Testing - Path traversal, privilege escalation",
        "Session Management - Cookie security, session fixation",
        "Input Validation - SQL injection, XSS, command injection",
        "Error Handling - Error codes, stack traces",
        "Cryptography - Weak algorithms, transport layer security",
        "Business Logic Testing - Logic flaws, workflow bypass",
        "Client-side Testing - DOM-based vulnerabilities, client-side controls"
    ]
    owasp_summary = "\n".join(owasp_topics)
except Exception as e:
    print(f"Error loading OWASP PDF: {str(e)}")
    owasp_content = ""
    owasp_summary = ""

# Ensure local SQLite DB and table exist for breach checks
def _init_breach_db():
    try:
        conn = sqlite3.connect("breachcheck.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS breaches (
                email TEXT PRIMARY KEY,
                breaches TEXT
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to initialize breach database: {str(e)}")

_init_breach_db()

# RapidAPI key for breachdirectory (move to env var for production)
RAPIDAPI_KEY = "58b753b14amshf248def4b86bc26p1adb7fjsn06bf4512491a"

#MySQL Configuration
# views.config['MYSQL_HOST'] = 'localhost'
# views.config['MYSQL_USER'] = 'root'
# views.config['MYSQL_PASSWORD'] = ''
# views.config['MYSQL_DB'] = 'college'

@views.route('/')
def index():
    return render_template("index.html")

@views.route('/about')
def about():
    return render_template("about.html")

@views.route('/service')
def service():
    return render_template("service.html")

@views.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        # Insert into MySQL database
        conn = pymysql.connect(host='localhost', user='root', password='ubuntu', database='college')
        cursor = conn.cursor()
        sql_query = "INSERT INTO sentinel (name, email, subject, message) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql_query, (name, email, subject, message))
        conn.commit()
        conn.close()
        
        return '<script>alert("Thank you! Your Message has been sent successfuly"); window.location.href="/contact";</script>'
    
    else:
        return render_template("contact.html")
    

@views.route('/policy')
def policy():
    return render_template("policy.html")

@views.route('/terms')
def terms():
    return render_template("terms.html")

@views.route('/ai-assistant')
def ai_assistant():
    return render_template("ai-assistant.html")

@views.route('/ai-assistant/chat', methods=['POST'])

def analyze_url_for_phishing(url):
    """
    Lightweight phishing detection function.
    Returns a phishing_score (0.0–1.0) and a list of suspicious indicators.
    """

    indicators = []
    score = 0.0

    # Rule 1: Suspicious use of numbers
    if re.search(r'\d{3,}', url):
        indicators.append("Contains unusual numeric patterns")
        score += 0.3

    # Rule 2: Keywords often used in phishing
    suspicious_keywords = ["login", "secure", "update", "verify", "account", "bank"]
    if any(word in url.lower() for word in suspicious_keywords):
        indicators.append("Suspicious keyword in URL")
        score += 0.3

    # Rule 3: Not using HTTPS
    if url.startswith("http://"):
        indicators.append("Uses insecure HTTP instead of HTTPS")
        score += 0.4

    # Rule 4: Special characters that may indicate obfuscation
    if "@" in url or "-" in url:
        indicators.append("Contains unusual symbols (@ or -)")
        score += 0.2

    # Cap score at 1.0
    score = min(score, 1.0)

    # If no indicators found, mark as likely safe
    if not indicators:
        indicators.append("No obvious phishing indicators found")

    return score, indicators

def ai_chat():
    try:
        data = request.json
        user_message = data.get('message', '')
        
        # Check if the message contains a URL for phishing detection
        url_match = re.search(r'https?://[\w\.-]+\.[a-zA-Z]{2,}[\w\.-/]*', user_message)
        is_phishing_check = False
        phishing_analysis = ""
        
        if url_match and any(term in user_message.lower() for term in ['check', 'safe', 'legitimate', 'phishing', 'suspicious']):
            is_phishing_check = True
            url = url_match.group(0)
            


        if is_phishing_check:
            phishing_score, phishing_indicators = analyze_url_for_phishing(url)
            
            if phishing_score > 0.7:
                risk_level = "**HIGH RISK**"
                recommendation = "This URL shows strong indicators of being a phishing site. Do not proceed or enter any personal information."
            elif phishing_score > 0.4:
                risk_level = "**MEDIUM RISK**"
                recommendation = "This URL shows some suspicious characteristics. Proceed with caution and verify the site through official channels."
            else:
                risk_level = "**LOW RISK**"
                recommendation = "This URL appears to be legitimate based on our analysis, but always remain vigilant."
                
            phishing_analysis = f"""URL Analysis: {url}\n\nRisk Assessment: {risk_level}\n\nIndicators:\n{phishing_indicators}\n\nRecommendation: {recommendation}"""
            query_type = "phishing_detection"
        else:
            # Process the message to determine the type of cybersecurity query
            query_type = determine_query_type(user_message)
        
        # Generate context based on query type
        context = generate_context(query_type, user_message)
        
        # Add PDF-specific knowledge for relevant queries
        if query_type == 'nist_framework':
            # Search for relevant content in NIST PDF based on user query
            nist_relevant_content = search_pdf_content(nist_content, user_message)
            context += f"\n\nRelevant NIST Framework content: {nist_relevant_content}"
        elif query_type == 'owasp_guide':
            # Search for relevant content in OWASP PDF based on user query
            owasp_relevant_content = search_pdf_content(owasp_content, user_message)
            context += f"\n\nRelevant OWASP Testing Guide content: {owasp_relevant_content}"
        
        # Check for service-specific keywords to suggest relevant services
        service_suggestions = recommend_services(user_message)
        
        # Send to Gemini with the enhanced context and formatting instructions
        if is_phishing_check:
            prompt = f"""{context}\n\nUser query: {user_message}\n\nPhishing analysis results:\n{phishing_analysis}\n\nProvide a helpful, accurate response focused on the phishing detection results above. Follow these formatting rules:\n1. Keep your response concise and direct\n2. Maintain the bold formatting for risk level\n3. Explain why the URL might be risky or safe\n4. Recommend specific protective actions\n5. Include the [phishing detection] tag"""
        else:
            prompt = f"""{context}\n\nUser query: {user_message}\n\nProvide a helpful, accurate response focused on cybersecurity. Follow these formatting rules:\n1. Keep your response concise and to the point (max 3-4 sentences per paragraph)\n2. Use **bold** for important terms or warnings\n3. Break content into short paragraphs with line breaks between them\n4. If relevant, include these service links: {service_suggestions}\n5. Don't use asterisks for bullet points, use proper markdown"""
        
        response = model.generate_content(prompt)
        
        # Process the response to ensure it's not too lengthy
        processed_response = process_ai_response(response.text)
        
        return jsonify({'response': processed_response, 'query_type': query_type})
    except Exception as e:
        print(f"Error in AI chat: {str(e)}")
        return jsonify({'response': 'Sorry, I encountered an error. Please try again later.', 'error': str(e)}), 500


def recommend_services(message):
    """Recommend relevant ShieldNet services based on user query."""
    message = message.lower()
    
    suggestions = []
    
    # Enhanced keyword matching for better service recommendations
    
    # Phishing detection keywords (handled directly in AI assistant)
    phishing_keywords = [
        'phishing', 'suspicious link', 'fake website', 'scam email', 'url check', 
        'website legitimate', 'suspicious site', 'fake login', 'email security',
        'suspicious url', 'fake bank', 'spoofed', 'credential', 'identity theft',
        'email verification', 'account alert', 'unusual activity', 'verify account'
    ]
    
    # Malware scan keywords
    malware_keywords = [
        'malware', 'virus', 'trojan', 'ransomware', 'infected', 'suspicious file',
        'spyware', 'adware', 'worm', 'backdoor', 'keylogger', 'rootkit', 
        'file scan', 'attachment check', 'download safety', 'executable', 
        'suspicious program', 'malicious code', 'file integrity'
    ]
    
    # Port scan keywords
    port_keywords = [
        'port', 'network', 'open ports', 'scan ip', 'ip address', 'server security',
        'firewall', 'network vulnerability', 'exposed service', 'network mapping',
        'port vulnerability', 'network security', 'server hardening', 'penetration testing',
        'network exposure', 'service discovery'
    ]
    
    
    
    # GuardCore keywords
    vm_keywords = [
        'sandbox', 'isolated environment', 'safe execution', 'test file', 
        'run safely', 'virtual machine', 'vm', 'safe analysis', 'suspicious program',
        'untrusted file', 'safe testing', 'malware analysis', 'isolation',
        'contained execution', 'safe runtime'
    ]
    
    # Phishing detection is now handled directly in the AI assistant without a button
    # No need to add phishing detection tag
    
    if any(keyword in message for keyword in malware_keywords):
        suggestions.append('[malware scan]')
    
    if any(keyword in message for keyword in port_keywords):
        suggestions.append('[port scan]')
    
    # Check for vulnerability assessment queries
    if any(keyword in message for keyword in ['vulnerability', 'exploit', 'patch', 'security hole', 'cve', 'weakness']):
        suggestions.append('[vulnerability scan]')
    
    # Check for sandbox/VM testing queries
    if any(keyword in message for keyword in ['sandbox', 'vm', 'virtual machine', 'test environment', 'isolated']):
        suggestions.append('[GuardCore]')
        
    # Limit to max 2 most relevant services to avoid cluttering the response
    if len(suggestions) > 2:
        suggestions = suggestions[:2]
    
    return ', '.join(suggestions) if suggestions else ''

def search_pdf_content(pdf_content, query):
    """Search for relevant content in PDF based on user query."""
    query_terms = query.lower().split()
    
    # Split PDF content into paragraphs
    paragraphs = pdf_content.split('\n\n')
    
    # Score paragraphs based on query term matches
    scored_paragraphs = []
    for para in paragraphs:
        if len(para.strip()) < 50:  # Skip very short paragraphs
            continue
        
        score = 0
        for term in query_terms:
            if term in para.lower():
                score += 1
        
        if score > 0:
            scored_paragraphs.append((para, score))
    
    # Sort by score and get top 3 paragraphs
    scored_paragraphs.sort(key=lambda x: x[1], reverse=True)
    top_paragraphs = [p[0] for p in scored_paragraphs[:3]]
    
    # Return concatenated paragraphs or a message if none found
    if top_paragraphs:
        return '\n\n'.join(top_paragraphs)
    else:
        return "No specific content found in the document for this query. Please ask a more specific question about the framework."

def process_ai_response(response):
    """Process AI response to ensure it's concise and properly formatted."""
    # Truncate if too long (over 2000 chars)
    if len(response) > 2000:
        # Find the last period before 2000 chars and cut there
        last_period = response[:2000].rfind('.')
        if last_period > 0:
            response = response[:last_period+1] + "\n\n[Response truncated for brevity. Ask for more details if needed.]"
        else:
            response = response[:1997] + "..."
    
    # Convert any plain text URLs to markdown links
    url_pattern = r'(https?://[\w\.-]+\.[a-zA-Z]{2,}[\w\.-/]*)'
    response = re.sub(url_pattern, r'[\1](\1)', response)
    
    # Ensure proper markdown formatting
    response = re.sub(r'\*\s+', '* ', response)  # Fix bullet points
    response = re.sub(r'\n{3,}', '\n\n', response)  # Remove excessive line breaks
    
    # Add contextual service suggestions based on content
    lower_response = response.lower()
    
    # Phishing detection is now handled directly in the AI assistant without a button
    if any(term in lower_response for term in ['phish', 'suspicious link', 'fake website', 'scam', 'email security']):
        response += '\n\nYou can ask me to check any URL by saying "Is this URL safe?" followed by the link.'
    
    # Add malware scan suggestion if relevant
    if '[malware scan]' not in response and any(term in lower_response for term in ['malware', 'virus', 'infected', 'trojan', 'ransomware']):
        response += '\n\nWant to scan a file for malware? Try our [malware scan] service.'
    
    # Add port scan suggestion if relevant
    if '[port scan]' not in response and any(term in lower_response for term in ['port', 'network security', 'firewall', 'server']):
        response += '\n\nCheck your network for vulnerabilities with our [port scan] service.'
    
    
    
    # Add GuardCore suggestion if relevant
    if '[GuardCore]' not in response and any(term in lower_response for term in ['sandbox', 'virtual machine', 'safe execution', 'isolated']):
        response += '\n\nSafely test suspicious files in our isolated [GuardCore] environment.'
    
    return response

def determine_query_type(message):
    """Determine the type of cybersecurity query."""
    message = message.lower()
    
    # Define keywords for different query types
    threat_keywords = ['malware', 'virus', 'phishing', 'ransomware', 'attack', 'hacked', 'suspicious', 'threat']
    damage_keywords = ['cost', 'damage', 'loss', 'financial', 'impact', 'estimate', 'risk']
    assistance_keywords = ['help', 'fix', 'solve', 'mitigate', 'prevent', 'protect', 'secure', 'solution']
    education_keywords = ['learn', 'explain', 'what is', 'how to', 'tutorial', 'guide', 'understand']
    
    # New keywords for NIST Framework and OWASP queries
    nist_keywords = ['nist', 'framework', 'cybersecurity framework', 'identify', 'protect', 'detect', 'respond', 'recover', 
                     'risk management', 'compliance', 'governance', 'security controls']
    owasp_keywords = ['owasp', 'web security', 'testing guide', 'penetration testing', 'web application', 'vulnerability', 
                      'security testing', 'web app security', 'injection', 'xss', 'csrf', 'authentication']
    
    # Check for NIST and OWASP specific queries first (higher priority)
    for keyword in nist_keywords:
        if keyword in message:
            return 'nist_framework'
    
    for keyword in owasp_keywords:
        if keyword in message:
            return 'owasp_guide'
    
    # Check for other keyword matches
    for keyword in threat_keywords:
        if keyword in message:
            return 'threat_identification'
    
    for keyword in damage_keywords:
        if keyword in message:
            return 'damage_estimation'
    
    for keyword in assistance_keywords:
        if keyword in message:
            return 'real_time_assistance'
    
    for keyword in education_keywords:
        if keyword in message:
            return 'user_education'
    
    # Default to general assistance
    return 'general_assistance'

def generate_context(query_type, user_message):
    """Generate context based on the query type."""
    contexts = {
        'threat_identification': """
        You are ShieldNet's specialized AI cybersecurity assistant focused on threat identification. 
        Your task is to analyze the user's description and identify potential cybersecurity threats such as malware, 
        vulnerabilities, phishing attempts, or other security risks. Provide specific details about the threat type, 
        how it typically operates, and its severity level (Low, Medium, High, Critical).
        """,
        
        'damage_estimation': """
        You are ShieldNet's specialized AI cybersecurity assistant focused on damage estimation. 
        Your task is to estimate potential financial and operational impacts of cybersecurity threats. 
        Consider factors like business size, industry averages for breaches, data recovery costs, 
        potential regulatory fines, and reputational damage. Provide a range of potential costs and 
        explain the factors that influence your estimation.
        """,
        
        'real_time_assistance': """
        You are ShieldNet's specialized AI cybersecurity assistant focused on providing real-time assistance. 
        Your task is to offer immediate, actionable steps to address the user's cybersecurity concern. 
        Provide step-by-step instructions that are clear and specific, prioritizing containment and 
        mitigation strategies. Include both immediate actions and longer-term solutions.
        """,
        
        'user_education': """
        You are ShieldNet's specialized AI cybersecurity assistant focused on user education. 
        Your task is to explain cybersecurity concepts in simple, accessible language without technical jargon. 
        Provide educational content that helps users understand security best practices, common threats, 
        and how to protect themselves online. Include analogies or examples when helpful.
        """,
        
        'general_assistance': """
        You are ShieldNet's specialized AI cybersecurity assistant. Your task is to provide helpful, 
        accurate information about cybersecurity topics. Focus on being clear, concise, and educational 
        while maintaining a professional tone. Provide practical advice when appropriate.
        """,
        
        'nist_framework': f"""
        You are ShieldNet's specialized AI cybersecurity assistant with expertise in the NIST Cybersecurity Framework.
        You have been trained on the NIST.CSWP.04162018.pdf document, which contains the official NIST Cybersecurity Framework.
        This makes you different from regular AI assistants that don't have access to this specialized knowledge.
        
        The NIST Cybersecurity Framework consists of five core functions:
        {nist_summary}
        
        Your task is to provide accurate, detailed information about the NIST Cybersecurity Framework based on this document.
        When responding, make it clear that your knowledge comes from being trained on the official NIST Cybersecurity Framework document.
        
        User query: {user_message}
        """,
        
        'owasp_guide': f"""
        You are ShieldNet's specialized AI cybersecurity assistant with expertise in web application security testing.
        You have been trained on the OWASP_Testing_Guide_v4.pdf document, which contains the official OWASP Testing Guide v4.
        This makes you different from regular AI assistants that don't have access to this specialized knowledge.
        
        The OWASP Testing Guide covers these key areas:
        {owasp_summary}
        
        Your task is to provide accurate, detailed information about web application security testing based on this document.
        When responding, make it clear that your knowledge comes from being trained on the official OWASP Testing Guide v4 document.
        
        User query: {user_message}
        """
    }
    
    return contexts.get(query_type, contexts['general_assistance'])

@views.route('/service/port-scanner')
def portScanner():
    return render_template("port-scanner.html")

@views.route('/service/malware-scanner')
def malwareScanner():
    return render_template("malware-scanner.html")

@views.route('/service/guardcore')
def GuardCore():
    return render_template("guardcore.html")

@views.route('/breach', methods=['GET', 'POST'])
def breachdetection():
    result = None
    batch_results = []
    if request.method == 'POST':
        # 1) Single email path
        email = request.form.get("email")
        if email and email.strip():
            api_result = query_breach_api(email.strip())
            # Prepare a sanitized result for the template to avoid printing raw API dicts
            if isinstance(api_result, dict) and api_result.get('status') == 'breached':
                breaches = api_result.get('breaches') or []
                # if API returned raw text, wrap it
                if not breaches and api_result.get('breaches_raw'):
                    breaches = [api_result.get('breaches_raw')]

                result = {
                    'status': 'breached',
                    'breaches': breaches
                }
            elif isinstance(api_result, dict) and api_result.get('status') == 'safe':
                result = {
                    'status': 'safe',
                    'message': api_result.get('message', 'No breaches found for this email.')
                }
            else:
                # Generic error or unexpected shape
                result = {
                    'status': api_result.get('status', 'error') if isinstance(api_result, dict) else 'error',
                    'message': api_result.get('message', str(api_result)) if isinstance(api_result, dict) else str(api_result)
                }

        # 2) Batch file path (CSV, TXT, or Excel)
        elif 'email_file' in request.files:
            file = request.files['email_file']
            if file and file.filename:
                filename_lower = file.filename.lower()
                try:
                    content = file.read()
                    emails_to_check = []

                    if filename_lower.endswith('.csv'):
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except Exception:
                            text = content.decode('latin-1', errors='ignore')
                        reader = csv.reader(io.StringIO(text))
                        for row in reader:
                            for cell in row:
                                candidate = cell.strip()
                                if candidate:
                                    emails_to_check.append(candidate)
                    elif filename_lower.endswith('.txt'):
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except Exception:
                            text = content.decode('latin-1', errors='ignore')
                        for line in text.splitlines():
                            candidate = line.strip()
                            if candidate:
                                emails_to_check.append(candidate)
                    elif filename_lower.endswith('.xlsx') or filename_lower.endswith('.xls'):
                        # Use pandas to read Excel into DataFrame, scan all cells for emails
                        try:
                            excel_stream = io.BytesIO(content)
                            # Read all sheets
                            xls = pd.ExcelFile(excel_stream)
                            for sheet_name in xls.sheet_names:
                                df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str)
                                for col in df.columns:
                                    for cell in df[col].dropna().astype(str).tolist():
                                        candidate = cell.strip()
                                        if candidate:
                                            emails_to_check.append(candidate)
                        except Exception as e:
                            raise Exception(f"Failed to parse Excel file: {str(e)}")

                    # De-duplicate while preserving order
                    seen = set()
                    deduped_emails = []
                    for e in emails_to_check:
                        if e not in seen:
                            seen.add(e)
                            deduped_emails.append(e)

                    # Process one at a time with a 3-second interval
                    for idx, e in enumerate(deduped_emails):
                        api_result = query_breach_api(e)
                        # Sanitize per-email results for display
                        if isinstance(api_result, dict) and api_result.get('status') == 'breached':
                            breaches = api_result.get('breaches') or []
                            if not breaches and api_result.get('breaches_raw'):
                                breaches = [api_result.get('breaches_raw')]
                            display_result = {'status': 'breached', 'breaches': breaches}
                        elif isinstance(api_result, dict) and api_result.get('status') == 'safe':
                            display_result = {'status': 'safe', 'message': api_result.get('message', '')}
                        else:
                            display_result = {'status': api_result.get('status', 'error') if isinstance(api_result, dict) else 'error', 'message': api_result.get('message', str(api_result)) if isinstance(api_result, dict) else str(api_result)}

                        batch_results.append({'email': e, 'result': display_result})
                        # Log for visibility in console
                        print(f"[BATCH {idx+1}/{len(deduped_emails)}] {e} -> {api_result}")
                        # Sleep between requests except after the last one
                        if idx < len(deduped_emails) - 1:
                            time.sleep(3)

                    result = {
                        'status': 'batch_complete',
                        'message': f'Processed {len(deduped_emails)} email(s).',
                    }
                except Exception as e:
                    result = {
                        'status': 'error',
                        'message': f'Failed to process file: {str(e)}'
                    }

    return render_template("breach.html", result=result, batch_results=batch_results)

def query_breach_api(email):
    """Placeholder for external breach API call.
    Currently checks local SQLite via check_email_in_db for demo purposes.
    Replace with real API integration as needed.
    """
    try:
        # First check local DB for a cached breach entry
        db_hit = check_email_in_db(email)
        if db_hit:
            # If the breaches column contains JSON or a joined string, try to parse it
            breaches_field = None
            try:
                # db_hit is a row tuple; breaches column is second column per schema
                breaches_field = db_hit[1]
                # try to parse JSON stored in DB
                parsed = json.loads(breaches_field)
                return {"status": "breached", "breaches": parsed}
            except Exception:
                # If parsing fails, return raw stored value as a single-element list
                return {"status": "breached", "breaches": [breaches_field]}

        # Not found locally — query the RapidAPI breachdirectory endpoint
        url = "https://breachdirectory.p.rapidapi.com/"
        headers = {
            'x-rapidapi-key': RAPIDAPI_KEY,
            'x-rapidapi-host': 'breachdirectory.p.rapidapi.com'
        }
        params = {"func": "auto", "term": email}

        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            # Try to parse JSON response
            try:
                data = resp.json()
            except Exception:
                data = None

            # If JSON contains results, treat as breached
            if data:
                # Normalize to a list of breach entries
                if data["success"] is False:
                    return "No breaches found for this email."
                else:
                    return f"This email is involved in {data['found']} breaches."
                breaches = []
                if isinstance(data, list):
                    breaches = data
                elif isinstance(data, dict):
                    # If dict contains a key with matches, try to extract
                    # Otherwise return the dict as single item
                    # Many breach-directory responses are lists; keep flexible
                    breaches = [data]

                return {"status": "breached", "breaches": breaches}

            # No data -> no breaches found
            text = resp.text.strip()
            if text:
                # If API returned plain text results, consider that as a hit
                return {"status": "breached", "breaches_raw": text}

            return {"status": "safe", "message": "No breaches found for this email."}
        else:
            # Non-200 from API
            return {"status": "error", "message": f"API error {resp.status_code}: {resp.text}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@views.route('/service/guardcore/download')
def download_file():
    file_path = '/home/ubuntu/Server/GuardCore/GuardCore.rar'
    return send_file(file_path, as_attachment=True)



# Phishing detection is now handled directly in the AI assistant

@views.route('/results/port-scan', methods=['POST'])
def scanPorts():
    target = request.form.get('target')
    port_range = request.form.get('portRange')

    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    url_regex = r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'


    if not target or not port_range or (not re.match(ip_regex, target) and not re.match(url_regex, target)):
        return "Error: Invalid target or port range", 400


    # Determine nmap arguments based on port range
    if port_range == 'all':
        ports = '-p-'
    else:  # Assume 'common'
        ports = '-p20,21,22,23,25,53,80,110,443'

    # Run nmap and capture its output
    result = subprocess.run(f'nmap -sC -sV {ports} -oX /home/ubuntu/Results/result.xml --stylesheet /home/ubuntu/Results/nmap-bootstrap.xsl {target}', shell=True, text=True, capture_output=True)
    subprocess.run(['xsltproc -o /home/ubuntu/Project/templates/results/result.html /home/ubuntu/Results/nmap-bootstrap.xsl /home/ubuntu/Results/result.xml'], shell=True)

    return render_template('/results/result.html')

@views.route('/api/scan', methods=['POST'])
def scan_file():
    # Get the uploaded file
    uploaded_file = request.files['file']
    
    if not uploaded_file:
        return jsonify({'error': 'No file uploaded'}), 400
    
    # VirusTotal API key
    api_key = '317d90e8d30b27cf62ca84a905f03f25f4848509df132b8dfaa15d9cbb7135b4'
    scan_url = 'https://www.virustotal.com/api/v3/'
    
    # Prepare headers with the API key
    headers = {
        'x-apikey': api_key
    }
    
    # Prepare the file data
    files = {
        'file': (uploaded_file.filename, uploaded_file.stream)
    }
    
    try:
        response = requests.post(scan_url + "files", files=files, headers=headers)
        
        if response.status_code == 200:
            sha256_hash = hashlib.sha256()
            uploaded_file.stream.seek(0)
            for chunk in iter(lambda: uploaded_file.stream.read(4096), b""):
                sha256_hash.update(chunk)
            sha256 = sha256_hash.hexdigest()

            return jsonify({'url' : f"https://www.virustotal.com/ui/file_behaviours/{sha256}_Zenbox/html"})
        
        else:
            return jsonify({'error': 'Failed to upload file to VirusTotal'}), response.status_code
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    






# function to check if email exists in DB
def check_email_in_db(email):
    conn = sqlite3.connect("breachcheck.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM breaches WHERE email=?", (email,))
    result = cursor.fetchone()
    conn.close()
    return result

@views.route("/")
def home():
    return render_template("index.html")

@views.route("/check_single", methods=["POST"])
def check_single():
    email = request.form.get("email")
    result = check_email_in_db(email)
    return render_template("result.html", email=email, result=result)

@views.route("/check_multiple", methods=["POST"])
def check_multiple():
    file = request.files["file"]
    emails = []
    results = []

    if file.filename.endswith(".csv") or file.filename.endswith(".txt"):
        content = file.read().decode("utf-8").splitlines()
        for line in content:
            email = line.strip()
            if email:
                emails.append(email)
                results.append((email, check_email_in_db(email)))

    return render_template("results.html", results=results)
#test
