import os
import json
import logging
import requests  # Add this import for DeepSeek API calls      
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from langchain.schema import HumanMessage
from langchain_openai import ChatOpenAI
from datetime import datetime  # Import datetime for timestamping analyses
from typing import Dict, List
from collections import Counter
from difflib import get_close_matches

# === Setup ===
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)

# === Environment Config ===
MODEL_SOURCE = os.getenv("SELECTED_MODEL", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.3"))
MODEL_ID = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "1000"))

# === METRIC CALCULATIONS ===
formulas = {
    "Cyber Hygiene Score": {
        "formula": "Cyber Hygiene Score = 100 - (Sum of (CVSS × Severity Weight) ÷ Total Endpoints)",
        "description": "Measures the overall health of the system by evaluating vulnerabilities and their severity."
    },
    "Scan Coverage": {
        "formula": "Scan Coverage = (Scanned Endpoints ÷ Total Endpoints) × 100",
        "description": "Measures how many assets have been scanned against the total known assets."
    },
    "Exploit Availability": {
        "formula": "Exploit Availability = (Exploitable CVEs ÷ Total CVEs) × 100", 
        "description": "Assesses the percentage of vulnerabilities that have known exploits."
    },
    "Vulnerability Density": {
        "formula": "Vulnerability Density = Total Vulnerabilities ÷ Number of Assets",
        "description": "Shows how many vulnerabilities exist per asset on average."
    },
    "Remediation Rate": {
        "formula": "Remediation Rate = (Remediated Issues ÷ Total Issues) × 100",
        "description": "Shows the proportion of vulnerabilities that have been fixed."
    },
    "Mean Time To Remediate (MTTR)": {
        "formula": "MTTR = Total Remediation Time ÷ Number of Remediated Issues",
        "description": "Calculates average time taken to fix a vulnerability."
    },
    "Security Posture": {
        "formula": "Security Posture = Weighted Average of all key metrics (e.g. Hygiene, Exploitability, Coverage)",
        "description": "An aggregate indicator combining multiple metrics into one risk score."
    },
    "Vendor Risk Rating": {
        "formula": "Vendor Risk Rating = f(Cyber Hygiene + Attack Surface Exposure + Data Exposure)",
        "description": "Assesses vendor risk based on vulnerability exposure, indexed data, and service surface."
    },
    "Attack Surface Index": {
        "formula": "Attack Surface Index = Sum of (Public IPs + Open Ports + Exposed Services + Discovered Subdomains)",
        "description": "Measures the total exposed attack surface of the system."
    },
    "Authentication Test Coverage": {
        "formula": "Authentication Test Coverage = (Authenticated Endpoints ÷ Total Endpoints Requiring Auth) × 100",
        "description": "Shows percentage of endpoints with authentication testing completed."
    },
    "Code Injection Points": {
        "formula": "Code Injection Points = Count of (SQLi + XSS + Other Injectable Points)",
        "description": "Total number of potential injection vulnerabilities found."
    },
    "Security Misconfigurations": {
        "formula": "Security Misconfigurations = Count of (Missing Headers + Unsafe CORS + Insecure Cookies)",
        "description": "Number of detected security configuration issues."
    },
    "TLS/SSL Security Score": {
        "formula": "TLS Score = f(Protocol_Support + Cert_Validity + Cipher_Strength)",
        "description": "Grades the strength of TLS/SSL implementation."
    },
    "DNS & Subdomain Exposure": {
        "formula": "DNS Exposure = Count of (Subdomains + Zone Transfer Vulns + Misconfigurations)",
        "description": "Measures exposure through DNS and subdomain configurations."
    },
    "Shadow IT Detection": {
        "formula": "Shadow IT = Count of (Discovered Assets - Known Assets)",
        "description": "Identifies unauthorized or unknown assets in the environment."
    },
    "Public Asset Exposure": {
        "formula": "Public Exposure = Count of (Indexed URLs + Shodan Entries + Public Subdomains)",
        "description": "Measures publicly visible or indexed assets."
    },
    "Top Vulnerabilities by Severity": {
        "formula": "Severity Groups = {High: CVSS ≥ 7, Medium: CVSS 4-6.9, Low: CVSS < 4}",
        "description": "Categorizes vulnerabilities by CVSS severity scores into high, medium, and low groups."
    },
    "Vulnerable Endpoints List": {
        "formula": "Vulnerable Endpoints = Count of Unique Endpoints with Vulnerabilities",
        "description": "Direct listing of endpoints flagged with one or more vulnerabilities from scan reports."
    },
    "Unpatched Ports/Services": {
        "formula": "Unpatched Services = Count of (Vulnerable_Ports + Services_with_CVEs)",
        "description": "Services identified on known vulnerable ports or flagged with CVEs in scan results."
    },
    "Retest Status": {
        "formula": "Delta = Current_Scan_Results - Previous_Baseline_Results",
        "description": "Compares current scan output to previous baseline to track changes."
    },
    "Open Port Heatmap": {
        "formula": "Heatmap = Frequency_Distribution(Open_Ports_Across_Scans)",
        "description": "Visualizes frequency distribution of open ports detected across all scans."
    },
    "Compliance Readiness": {
        "formula": "Compliance % = (Compliant Checks ÷ Total Required Checks) × 100",
        "description": "Calculated by mapping discovered issues to OWASP Top 10, CIS benchmarks, and showing % of compliant vs non-compliant checks."
    },
    "Service Fingerprinting": {
        "formula": "Service_Info = Detect(Service_Version + Protocol + Configuration)",
        "description": "Identifies and catalogs detected services, versions, and configurations."
    }
}

# === Load JSON Scan Data ===
def load_scan_data(path: str = 'test.json') -> dict:
    try:
        # Get the directory containing the current script
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Construct absolute path to test.json
        json_path = os.path.join(current_dir, path)
        
        logger.info(f"Attempting to load scan data from: {json_path}")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            logger.info("Successfully loaded scan data")

        required_fields = ["cyber_hygiene_score", "attack_surface_index", 
                         "combined_security_score", "scan_date"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
        return data

    except FileNotFoundError:
        logger.error(f"Could not find test.json at {json_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format in test.json: {e}")
        raise
    except Exception as e:
        logger.exception("Error loading scan data")
        raise

try:
    scan_data = load_scan_data()
    scan_date = scan_data.get("scan_date")
except Exception as e:
    logger.critical(f"Startup failure: {e}")
    raise SystemExit("Terminating app due to scan data load failure.")

# === Initialize LLM ===
def initialize_model():
    if MODEL_SOURCE == "openai":
        if not OPENAI_API_KEY:
            raise ValueError("Missing OPENAI_API_KEY")
        logger.info("Using OpenAI model")
        return ChatOpenAI(
            temperature=TEMPERATURE,
            model_name=MODEL_ID,
            openai_api_key=OPENAI_API_KEY
        )
    else:
        raise ValueError(f"Unsupported model source: {MODEL_SOURCE}")

# Initialize the model
try:
    llm = initialize_model()
    logger.info(f"Model initialized successfully: {MODEL_SOURCE}")
except Exception as e:
    logger.critical(f"Model initialization failed: {e}")
    raise SystemExit("Terminating app due to model initialization failure.")

# === Security Phrases Dictionary ===
SECURITY_PHRASES = {
    'vulnerability': [
        'vulnerability', 'vulnerabilities', 'cve', 'exploit', 'weakness',
        'critical vulnerabilities', 'high-risk vulnerabilities', 'severity level',
        'injection flaw', 'security flaw', 'exploit', 'weakness'],
    'compliance': ['compliance', 'standard', 'regulation', 'requirement', 'audit'],
    'authentication': ['auth', 'login', 'credential', 'password', 'session'],
    'encryption': ['encrypt', 'cipher', 'crypto', 'tls', 'ssl'],
    'configuration': ['config', 'setting', 'parameter', 'setup', 'misconfiguration'],
    'access_control': ['access', 'permission', 'privilege', 'role', 'authorization'],
    'network': ['network', 'firewall', 'port', 'protocol', 'traffic'],
    'infrastructure': ['infrastructure', 'server', 'cloud', 'platform', 'host'],
    'monitoring': ['monitor', 'alert', 'log', 'audit', 'track'],
    'incident': ['incident', 'breach', 'attack', 'compromise', 'threat'],
    'risk_severity': ['critical', 'high-risk', 'severity', 'risk level', 'grouped by','top vulnerabilities', 'most critical', 'highest risk'],
    'injection': [
        'injection', 'sql injection', 'xss', 'command injection',
        'code injection', 'injectable', 'injection flaw'
    ]

}

# === Metric Lookup Enhancement ===
def get_relevant_metrics(question: str) -> list:
    """Find metrics relevant to the user's question"""
    return [
        {"name": name, **info}
        for name, info in formulas.items()
        if any(term.lower() in question.lower() for term in name.split())
    ]

# === Alert Analysis Functions ===
def get_risk_level(scan_data: Dict) -> str:
    """Calculate risk level based on scan data metrics"""
    hygiene_score = scan_data.get("cyber_hygiene_score", {}).get("score", 0)
    attack_surface = scan_data.get("attack_surface_index", {}).get("score", 0)
    
    if hygiene_score < 50 or attack_surface > 80:
        return "Critical"
    elif hygiene_score < 70 or attack_surface > 60:
        return "High"
    elif hygiene_score < 85 or attack_surface > 40:
        return "Medium"
    else:
        return "Low"

def summarize_alerts(alerts: List[Dict]) -> Dict:
    """Analyze and summarize alerts from scan data"""
    alert_summary = {
        "unique_types": Counter(alert["wascid"] for alert in alerts),
        "total_count": len(alerts),
        "risk_levels": Counter(),
        "critical_alerts": [],
        "remediation_steps": []
    }
    
    # Process each alert
    for alert in alerts:
        risk_level = alert.get("risk", "Unknown")
        alert_summary["risk_levels"][risk_level] += 1
        
        if risk_level in ["High", "Critical"]:
            alert_summary["critical_alerts"].append({
                "type": alert.get("wascid"),
                "description": alert.get("description", "No description available")
            })
            
        if "solution" in alert:
            alert_summary["remediation_steps"].append({
                "type": alert.get("wascid"),
                "solution": alert["solution"]
            })
    
    return alert_summary

# Enhance get_security_context to handle more data fields
def get_security_context(question: str, scan_data: dict) -> dict:
    """Get comprehensive security context from scan data"""
    
    context = {
        "metrics": {
            "cyber_hygiene": scan_data['cyber_hygiene_score']['score'],
            "cyber_hygiene_grade": scan_data['cyber_hygiene_score']['grade'],
            "attack_surface": scan_data['attack_surface_index']['score'],
            "combined_score": scan_data['combined_security_score']
        },
        "alerts": {
            "total": len(scan_data.get("alerts", [])),
            "by_risk_level": Counter(
                alert.get("risk", "Unknown") 
                for alert in scan_data.get("alerts", [])
            ),
            "critical": [
                alert for alert in scan_data.get("alerts", [])
                if alert.get("riskcode") == "3" or alert.get("risk") == "Critical"
            ],
            "high": [
                alert for alert in scan_data.get("alerts", [])
                if alert.get("riskcode") == "2" or alert.get("risk") == "High"
            ],
            "details": scan_data.get("alerts", [])
        },
        "compliance": {
            "owasp": {
                "total_issues": scan_data['compliance_readiness']['total_owasp_issues'],
                "compliance_score": scan_data['compliance_readiness']['owasp_compliance'],
                "findings": scan_data['compliance_readiness']['owasp_findings']
            },
            "cis": {
                "compliance_score": scan_data['compliance_readiness']['cis_compliance'],
                "findings": scan_data['compliance_readiness']['cis_findings']
            },
            "overall_score": scan_data['compliance_readiness']['overall_compliance_score']
        },
        "security_config": {
            "misconfigurations": scan_data['security_misconfigurations']['total_misconfigurations'],
            "missing_headers": scan_data['security_misconfigurations']['missing_security_headers'],
            "insecure_cookies": scan_data['security_misconfigurations']['insecure_cookies']
        },
        "attack_surface": {
            "score": scan_data['attack_surface_index']['score'],
            "exposed_services": scan_data['attack_surface_index']['metrics']['exposed_services'],
            "open_ports": scan_data['attack_surface_index']['metrics']['open_ports'],
            "public_ips": scan_data['attack_surface_index']['metrics']['public_ips']
        },
        "vendor_risk": {
            "rating": scan_data['vendor_risk_rating']['numeric_rating'],
            "grade": scan_data['vendor_risk_rating']['letter_grade'],
            "risk_level": scan_data['vendor_risk_rating']['risk_level'],
            "recommendation": scan_data['vendor_risk_rating']['recommendation']
        },
        "scan_info": {
            "date": scan_data['scan_date'],
            "url": scan_data['url']
        }
    }
    
    return context

# Enhance validation function while keeping existing checks
def validate_security_question(question: str, scan_data: dict) -> tuple[bool, str]:
    """Enhanced validation with fuzzy matching and phrase detection"""
    
    question_lower = question.lower()
    
    # Check required data fields exist
    required_fields = {
        'cyber_hygiene_score': ['score', 'grade'],
        'attack_surface_index': ['score'],
        'combined_security_score': None
    }
    
    for field, subfields in required_fields.items():
        if field not in scan_data:
            logger.warning(f"Missing required field: {field}")
            continue
        if subfields:
            for subfield in subfields:
                if subfield not in scan_data[field]:
                    logger.warning(f"Missing subfield {subfield} in {field}")

    # Check for phrase matches
    for category, phrases in SECURITY_PHRASES.items():
        if any(phrase in question_lower for phrase in phrases):
            return True, f"Matched security phrase category: {category}"

    # Check existing security topics
    security_topics = {
        # Core Security Metrics
        'score': ['cyber_hygiene_score', 'combined_security_score'],
        'hygiene': ['cyber_hygiene_score'],
        'grade': ['cyber_hygiene_score'],
        'security': ['cyber_hygiene_score', 'combined_security_score'],
        
        # Compliance
        'compliance': ['compliance_readiness'],
        'owasp': ['compliance_readiness'],
        'cis': ['compliance_readiness'],
        'benchmark': ['compliance_readiness'],
        
        # Vulnerabilities & Risks
        'vulnerability': ['alerts'],
        'alert': ['alerts'],
        'risk': ['alerts', 'vendor_risk_rating'],
        
        # Add remediation-related mappings
        'remediation': ['alerts', 'security_misconfigurations'],
        'fix': ['alerts', 'security_misconfigurations'],
        'solve': ['alerts', 'security_misconfigurations'],
        'mitigate': ['alerts', 'security_misconfigurations'],
        'patch': ['alerts', 'security_misconfigurations'],
        'rate': ['alerts', 'security_misconfigurations'],
        
        # Rest of existing mappings
        'issue': ['alerts', 'security_misconfigurations'],
        'critical': ['alerts'],
        'high': ['alerts'],
        
        # Infrastructure
        'attack surface': ['attack_surface_index'],
        'port': ['attack_surface_index'],
        'service': ['attack_surface_index'],
        'exposed': ['attack_surface_index'],
        
        # Specific Security Areas
        'misconfiguration': ['security_misconfigurations'],
        'header': ['security_misconfigurations'],
        'cookie': ['security_misconfigurations'],
        'vendor': ['vendor_risk_rating'],
        
        # Add DNS and subdomain related mappings
        'subdomain': ['attack_surface_index', 'dns_exposure'],
        'dns': ['attack_surface_index', 'dns_exposure'],
        'domain': ['attack_surface_index', 'dns_exposure'],
        'discovered': ['attack_surface_index', 'dns_exposure'],
        
        # Add vulnerability density mapping
        'density': ['alerts', 'attack_surface_index'],
        
        # Add scan coverage to security_topics
        'coverage': ['scan_coverage', 'cyber_hygiene_score'],
        'scan': ['scan_coverage', 'cyber_hygiene_score'],
        
        # Add expanded metric mappings
        'posture': ['cyber_hygiene_score', 'combined_security_score'],
        'status': ['cyber_hygiene_score', 'attack_surface_index'],
        'health': ['cyber_hygiene_score', 'combined_security_score'],
        'combined': ['combined_security_score'],
        'surface': ['attack_surface_index'],
        'exposure': ['attack_surface_index', 'dns_exposure'],
    }
    
    # Dynamic keyword extraction from scan data
    dynamic_keywords = set()
    
    # Extract from alerts
    for alert in scan_data.get('alerts', []):
        if alert.get('name'):
            dynamic_keywords.add(alert['name'].lower())
        if alert.get('wascid'):
            dynamic_keywords.add(f"wasc-{alert['wascid']}")
        if alert.get('reference'):
            dynamic_keywords.add(alert['reference'].lower())
    
    # Extract from OWASP findings
    if 'compliance_readiness' in scan_data:
        for finding in scan_data['compliance_readiness'].get('owasp_findings', {}):
            dynamic_keywords.add(finding.lower())
    
    # Extract from security misconfigurations
    if 'security_misconfigurations' in scan_data:
        headers = scan_data['security_misconfigurations'].get('missing_headers', {}).get('headers', [])
        dynamic_keywords.update(h.lower() for h in headers)
    
    # Combine with base keywords
    base_keywords = [
        'cyber hygiene', 'risk', 'vulnerability', 'csrf', 'cookie',
        'tls', 'port', 'scan', 'csp', 'misconfiguration', 'score',
        'grade', 'rating', 'alert', 'critical', 'high', 'medium', 'low',
        'exposure', 'remediation', 'compliance', 'owasp', 'cis'
    ]
    all_keywords = list(dynamic_keywords) + base_keywords
    
    # Check exact matches first using existing logic
    matches = []
    for keyword, data_paths in security_topics.items():
        if keyword in question_lower:
            if any(path in scan_data for path in data_paths):
                matches.append(keyword)
    
    if matches:
        return True, f"Direct match: {', '.join(matches)}"
    
    # Try fuzzy matching if no exact matches
    fuzzy_matches = get_close_matches(question_lower, all_keywords, n=3, cutoff=0.6)
    if fuzzy_matches:
        return True, f"Similar topics found: {', '.join(fuzzy_matches)}"
    
    return False, "Question not related to security scan data. Try asking about scores, compliance, or security status."

@app.route('/ask', methods=['POST'])
def ask():
    try:
        payload = request.get_json(force=True)
        question = payload.get("question", "").strip()

        if not question:
            return jsonify({
                "error": "Missing Question",
                "message": "Please enter a security-related question"
            }), 400

        # Validate question
        is_valid, reason = validate_security_question(question, scan_data)
        
        if not is_valid:
            return jsonify({
                "error": "Invalid Question",
                "message": "This question cannot be answered with security scan data",
                "reason": reason
            }), 400

        # Use the original function name
        security_context = get_security_context(question, scan_data)
        response = generate_security_response(question, scan_data, security_context)
        logger.info(f"Generated response for question: {question}")
        
        return jsonify({"response": response})

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return jsonify({
            "error": "Analysis Failed",
            "message": "Failed to process security analysis",
            "details": str(e)
        }), 500

def get_question_type(question: str) -> str:
    """Enhanced question type detection with phrase matching"""
    question_lower = question.lower()
    
    # Check for phrase matches first
    for category, phrases in SECURITY_PHRASES.items():
        if any(phrase in question_lower for phrase in phrases):
            return category
    
    # Fall back to existing categories
    categories = {
        'metrics': ['score', 'grade', 'rating', 'posture', 'attack surface', 'combined'],
        # ... rest of existing categories ...
    }
    
    for category, keywords in categories.items():
        if any(keyword in question_lower for keyword in keywords):
            return category
            
    return 'general'

def generate_security_response(question: str, scan_data: dict, context: dict) -> str:
    question_lower = question.lower()

    # Enhanced Vulnerability Analysis
    if any(term in question_lower for term in [
        'vulnerability', 'vulnerabilities', 'cve', 'exploit', 
        'injection', 'severity', 'critical', 'high-risk', 'grouped'
    ]):
        alerts = scan_data.get('alerts', [])
        if not alerts:
            return """## Vulnerability Analysis
            
No vulnerability data found in the current scan."""

        # Categorize vulnerabilities
        critical = [a for a in alerts if a.get('risk', '').lower() == 'critical']
        high = [a for a in alerts if a.get('risk', '').lower() == 'high']
        injection = [
            a for a in alerts 
            if any(term in str(a).lower() for term in ['injection', 'sqli', 'xss'])
        ]
        
        # Find CVEs and exploitable issues
        cve_related = [
            a for a in alerts 
            if any('cve-' in str(v).lower() for v in a.values())
        ]
        exploit_mentions = [
            a for a in alerts 
            if any('exploit' in str(v).lower() for v in a.values())
        ]

        # Build response based on question focus
        if "critical" in question_lower:
            return f"""
## Critical Vulnerabilities Analysis

### Summary
• **Total Critical Issues**: {len(critical)}
• **Exploitable CVEs**: {len([v for v in critical if v in cve_related])}
• **Risk Level**: **{get_risk_level(scan_data)}**

### Critical Findings
{chr(10).join(f"• **{vuln.get('alert', 'Unknown')}**\n  - Impact: {vuln.get('description', 'No description')}\n  - Solution: {vuln.get('solution', 'No solution provided')}" 
              for vuln in critical[:5])}

### Required Actions
1. **Immediate Steps**:
   • Patch all critical vulnerabilities
   • Apply temporary mitigations
   • Review affected systems

2. **Documentation**:
   • Update risk register
   • Document fixes applied
   • Track remediation progress
"""

        elif "injection" in question_lower:
            return f"""
## Injection Vulnerabilities Analysis

### Current Status
• **Total Injection Issues**: {len(injection)}
• **Critical Severity**: {len([v for v in injection if v in critical])}
• **High Severity**: {len([v for v in injection if v in high])}

### Injection Findings
{chr(10).join(f"• **{vuln.get('alert', 'Unknown')}**\n  - Type: {vuln.get('type', 'Unknown')}\n  - Impact: {vuln.get('description', 'No description')}\n  - Fix: {vuln.get('solution', 'No solution provided')}" 
              for vuln in injection[:5])}

### Required Actions
1. **Priority Steps**:
   • Implement input validation
   • Add parameterized queries
   • Update security controls

2. **Security Controls**:
   • Input sanitization
   • Output encoding
   • Regular testing
"""

        elif any(term in question_lower for term in ['cve', 'exploit']):
            return f"""
## CVE and Exploit Analysis

### Current Status
• **CVE-Related Issues**: {len(cve_related)}
• **Exploit Mentions**: {len(exploit_mentions)}
• **Critical CVEs**: {len([v for v in cve_related if v in critical])}

### Top CVE Findings
{chr(10).join(f"• **{vuln.get('alert', 'Unknown')}**\n  - CVE: {vuln.get('otherinfo', 'No CVE listed')}\n  - Risk: {vuln.get('risk', 'Unknown')}\n  - Fix: {vuln.get('solution', 'No solution provided')}" 
              for vuln in cve_related[:5])}

### Exploitability Assessment
• High Risk: {len([v for v in exploit_mentions if v in critical])} critical issues
• Medium Risk: {len([v for v in exploit_mentions if v in high])} high-risk issues
• Total Exploitable: {len(exploit_mentions)} issues

### Required Actions
1. **Critical Steps**:
   • Patch CVE-related issues
   • Mitigate exploit risks
   • Update vulnerable components

2. **Monitoring Plan**:
   • Daily CVE tracking
   • Weekly exploit checks
   • Monthly security review
"""

        else:
            # Group vulnerabilities by severity
            severity_groups = {}
            for alert in alerts:
                severity = alert.get('risk', 'Unknown')
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(alert)

            return f"""
## Comprehensive Vulnerability Analysis

### Overview
• **Total Vulnerabilities**: {len(alerts)}
• **Critical Issues**: {len(critical)}
• **High-Risk Issues**: {len(high)}
• **CVE-Related**: {len(cve_related)}

### Severity Distribution
{chr(10).join(f"• **{level}**: {len(vulns)} issues ({(len(vulns)/len(alerts)*100):.1f}%)" 
              for level, vulns in severity_groups.items() if vulns)}

### Key Findings
• Most Critical: {critical[0].get('alert', 'None') if critical else 'No critical issues'}
• Top High-Risk: {high[0].get('alert', 'None') if high else 'No high-risk issues'}
• Injection Issues: {len(injection)}
• Exploitable CVEs: {len([v for v in cve_related if v in critical or v in high])}

### Required Actions
1. **Immediate Steps**:
   • Address {len(critical)} critical issues
   • Fix {len(high)} high-risk findings
   • Review {len(cve_related)} CVE-related issues

2. **Monitoring Plan**:
   • Daily vulnerability scans
   • Weekly status updates
   • Monthly trend analysis
"""

    # CSRF Analysis
    if 'csrf' in question_lower:
        csrf_alerts = [a for a in scan_data.get('alerts', []) 
                      if 'csrf' in a.get('alert', '').lower()]
        
        if not csrf_alerts:
            return """## CSRF Security Status
• No CSRF vulnerabilities detected in current scan
• Continue monitoring for CSRF risks
• Maintain existing CSRF protections"""
        
        return f"""
## CSRF Security Analysis

### Current Findings
• **Total CSRF Issues**: {len(csrf_alerts)}
• Risk Level: **{get_risk_level(scan_data)}**

### Detected Issues
{chr(10).join(f"• **{alert.get('alert', 'Unknown')}**:\n  - Impact: {alert.get('description', 'No description')}\n  - Fix: {alert.get('solution', 'No solution provided')}" 
              for alert in csrf_alerts)}

### Required Actions
1. **Immediate Steps**:
   • Implement CSRF tokens
   • Validate request origins
   • Add SameSite cookie attributes

2. **Security Controls**:
   • Review form submissions
   • Update CSRF protections
   • Monitor for bypasses
"""

    # Cookie Security Analysis
    if 'cookie' in question_lower:
        cookie_alerts = [a for a in scan_data.get('alerts', []) 
                        if 'cookie' in a.get('alert', '').lower()]
        insecure_cookies = context['security_config']['insecure_cookies']
        
        return f"""
## Cookie Security Analysis

### Current Status
• **Insecure Cookies**: {insecure_cookies}
• Cookie-Related Alerts: {len(cookie_alerts)}
• Security Grade: {context['metrics']['cyber_hygiene_grade']}

### Cookie Issues
{chr(10).join(f"• **{alert.get('alert', 'Unknown')}**:\n  - Risk: {alert.get('risk', 'Unknown')}\n  - Solution: {alert.get('solution', 'No solution provided')}" 
              for alert in cookie_alerts[:3])}

### Required Controls
1. **Security Attributes**:
   • Set HttpOnly flag
   • Enable Secure flag
   • Configure SameSite

2. **Implementation**:
   • Review cookie settings
   • Update session management
   • Implement secure defaults
"""

    # CSP Analysis
    if any(term in question_lower for term in ['csp', 'content security policy']):
        headers = context['security_config']['missing_headers'].get('headers', [])
        csp_missing = any('content-security-policy' in h.lower() for h in headers)
        
        return f"""
## Content Security Policy Status

### Current Implementation
• **CSP Status**: {'Missing' if csp_missing else 'Present'}
• Risk Level: **{get_risk_level(scan_data)}**
• Security Grade: {context['metrics']['cyber_hygiene_grade']}

### Security Impact
• XSS Protection: {'Weakened' if csp_missing else 'Enhanced'}
• Inline Scripts: {'Unrestricted' if csp_missing else 'Controlled'}
• Resource Loading: {'Uncontrolled' if csp_missing else 'Restricted'}

### Required Actions
1. **Implementation Steps**:
   • {'Implement CSP header' if csp_missing else 'Review CSP policies'}
   • Configure secure defaults
   • Enable reporting

2. **Policy Requirements**:
   • Define trusted sources
   • Control resource loading
   • Monitor violations
"""

    # Vulnerability Assessment
    if any(term in question_lower for term in ['vulnerability', 'cve', 'exploit', 'weakness']):
        vulnerabilities = context['alerts']
        critical_vulns = [v for v in vulnerabilities['details'] if v.get('risk') == 'Critical']
        high_vulns = [v for v in vulnerabilities['details'] if v.get('risk') == 'High']
        
        return f"""
## Vulnerability Assessment

### Current Vulnerability Status
• **Total Vulnerabilities Detected**: {vulnerabilities['total_count']}
• **Critical Vulnerabilities**: {len(critical_vulns)}
• **High-Risk Vulnerabilities**: {len(high_vulns)}
• **Medium and Low Risks**: {vulnerabilities['total_count'] - len(critical_vulns) - len(high_vulns)}

### Vulnerability Breakdown by Risk Level
{chr(10).join(f"• **{level}**: {count} vulnerabilities" 
              for level, count in vulnerabilities['by_risk_level'].items())}

### Top Critical Vulnerabilities
{chr(10).join(f"• **{vuln.get('name', 'Unnamed')}**: {vuln.get('description', 'No description')}" 
              for vuln in critical_vulns[:3])}

### Recommended Actions
• **Immediate**: Remediate all critical vulnerabilities
• **High Risk**: Prioritize patching and mitigation
• Regularly scan for new vulnerabilities
"""

    # Compliance Analysis
    if any(term in question_lower for term in ['compliance', 'cis', 'owasp', 'benchmark']):
        owasp_issues = context['compliance']['owasp']
        cis_issues = context['compliance']['cis']
        
        return f"""
## Compliance Analysis

### OWASP Compliance Status
• **Total OWASP Issues**: {owasp_issues['total_issues']}
• **Compliance Score**: {owasp_issues['compliance_score']}%
• **Findings**: {owasp_issues['findings']}

### CIS Compliance Status
• **CIS Compliance Score**: {cis_issues['compliance_score']}%
• **Findings**: {cis_issues['findings']}

### Overall Compliance Status
• **Overall Score**: {context['compliance']['overall_score']}%
• **Risk Level**: {get_risk_level(scan_data)}

### Recommendations
• Address high-risk OWASP and CIS findings
• Improve security configurations
• Regular compliance audits
"""

    # Infrastructure Security
    if any(term in question_lower for term in ['attack surface', 'exposed', 'ports', 'services']):
        attack_surface = context['attack_surface']
        
        return f"""
## Infrastructure Security Analysis

### Current Attack Surface
• **Attack Surface Score**: {attack_surface['score']}/10
• **Exposed Services**: {attack_surface['exposed_services']}
• **Open Ports**: {attack_surface['open_ports']}
• **Public IPs**: {attack_surface['public_ips']}

### Security Configuration Issues
• Missing Security Headers: {len(context['security_config']['missing_headers'].get('headers', []))}
• Insecure Cookies: {context['security_config']['insecure_cookies']}
• Total Misconfigurations: {context['security_config']['misconfigurations']}

### Recommendations
• Harden server configurations
• Implement missing security headers
• Regularly review exposed services and open ports
"""

    # Risk Level Analysis
    if any(term in question_lower for term in ['risk level', 'most alerts', 'alert level']):
        alert_counts = context['alerts']['by_risk_level']
        max_risk = max(alert_counts.items(), key=lambda x: x[1])
        critical_count = len(context['alerts']['critical'])
        high_count = len(context['alerts']['high'])
        
        return f"""
## Comprehensive Risk Level Analysis

### Risk Level Distribution
{chr(10).join(f"• **{level}**: {count} alerts ({(count/context['alerts']['total']*100):.1f}%)" 
              for level, count in alert_counts.items())}

### Most Prevalent Risk Level
• **{max_risk[0]}** level with {max_risk[1]} alerts
• Represents {(max_risk[1]/context['alerts']['total']*100):.1f}% of total alerts

### Critical Security Status
• Critical Issues: {critical_count} alerts
• High-Risk Issues: {high_count} alerts
• Combined Critical/High: {critical_count + high_count} ({((critical_count + high_count)/context['alerts']['total']*100):.1f}% of total)

### Overall Security Impact
• Current Risk Level: **{get_risk_level(scan_data)}**
• Security Grade: {context['metrics']['cyber_hygiene_grade']}
• Attack Surface Score: {context['metrics']['attack_surface']}/10

### Required Actions
1. **Immediate Steps**:
   • {'Address Critical findings immediately' if critical_count > 0 else 'Monitor existing controls'}
   • {'Prioritize High-risk remediation' if high_count > 0 else 'Maintain security posture'}

2. **Recommended Controls**:
   • Implement security patches for Critical issues
   • Review security configurations
   • Schedule regular vulnerability assessments

3. **Monitoring Requirements**:
   • Daily review of Critical findings
   • Weekly review of High-risk issues
   • Monthly trend analysis
"""

    # OWASP Analysis
    if 'owasp' in question_lower:
        owasp_data = context['compliance']['owasp']
        misconfigs = context['security_config']
        
        return f"""
## Comprehensive OWASP Security Analysis

### Current Compliance Status
• **Total OWASP Issues**: {owasp_data['total_issues']}
• **Compliance Score**: {owasp_data['compliance_score']}%
• **Overall Status**: {"**Non-Compliant**" if owasp_data['compliance_score'] < 80 else "Compliant"}

### OWASP Top 10 Breakdown
{chr(10).join(f"• **{category}**:\n  - {count} {'issue' if count == 1 else 'issues'}\n  - Risk Level: {get_risk_level(scan_data)}\n  - Requires: {'**Immediate Action**' if count > 0 else 'Monitoring'}" 
              for category, count in owasp_data['findings'].items())}

### Security Configuration Status
• Missing Security Headers: {len(misconfigs['missing_headers'].get('headers', []))}
• Insecure Cookies Found: {misconfigs['insecure_cookies']}
• Total Misconfigurations: {misconfigs['misconfigurations']}

### Impact Assessment
• Current Security Grade: {context['metrics']['cyber_hygiene_grade']}
• Attack Surface Score: {context['metrics']['attack_surface']}/10
• Combined Security Score: {context['metrics']['combined_score']}/100

### Required Actions
1. **Critical Fixes**:
   • Implement missing security headers
   • Address OWASP Top 10 violations
   • Fix insecure cookie configurations

2. **Security Hardening**:
   • Regular OWASP compliance scans
   • Security architecture review
   • Developer security training

3. **Monitoring Plan**:
   • Daily vulnerability scans
   • Monthly penetration testing
   • Quarterly security training
   • Regular code security reviews
"""

    # Remediation Analysis
    if any(term in question_lower for term in ['remediation', 'fix', 'solve', 'mitigate', 'patch', 'rate']):
        alerts = scan_data.get('alerts', [])
        total_issues = len(alerts)
        fixed_issues = len([a for a in alerts if a.get('status') == 'fixed'])
        remediation_rate = (fixed_issues / total_issues * 100) if total_issues > 0 else 0
        
        return f"""
## Remediation Analysis

### Current Status
• **Remediation Rate**: {remediation_rate:.1f}%
• Total Issues Found: {total_issues}
• Issues Fixed: {fixed_issues}
• Pending Remediation: {total_issues - fixed_issues}

### Priority Issues
• Critical Issues: {len([a for a in alerts if a.get('risk') == 'Critical'])}
• High-Risk Issues: {len([a for a in alerts if a.get('risk') == 'High'])}

### Recent Fixes
{chr(10).join(f"• {alert.get('name', 'Unknown Issue')}: {alert.get('status', 'Status not available')}" 
              for alert in alerts[:3] if alert.get('status') == 'fixed')}

### Action Items
• {'**Immediate attention required**' if remediation_rate < 50 else 'Continue remediation efforts'}
• Prioritize {len([a for a in alerts if a.get('risk') == 'Critical'])} critical findings
• Schedule fixes for {len([a for a in alerts if a.get('risk') == 'High'])} high-risk issues
"""

    # Security Configuration Analysis
    if any(term in question_lower for term in ['cookie', 'header', 'misconfiguration', 'configuration']):
        security_config = context['security_config']
        
        return f"""
## Security Configuration Analysis

### Cookie Security Status
• **Insecure Cookies Found**: {security_config['insecure_cookies']}
• **Total Misconfigurations**: {security_config['misconfigurations']}

### Security Headers
• **Missing Headers**: {len(security_config['missing_headers'].get('headers', []))}
• Headers List: {', '.join(security_config['missing_headers'].get('headers', ['None']))}

### Impact Assessment
• Risk Level: **{get_risk_level(scan_data)}**
• Security Grade: {context['metrics']['cyber_hygiene_grade']}

### Required Actions
1. **Cookie Security Fixes**:
   • Review and secure insecure cookies
   • Implement secure cookie attributes
   • Enable HTTP-only flags

2. **Header Implementation**:
   • Add missing security headers
   • Configure CSP policies
   • Enable HSTS

3. **Regular Checks**:
   • Weekly configuration reviews
   • Monthly security assessments
   • Automated config scanning
"""

    # Add DNS/Subdomain Analysis handler
    if any(term in question_lower for term in ['subdomain', 'dns', 'domain', 'discovered']):
        attack_surface = context['attack_surface']
        
        return f"""
## DNS and Subdomain Analysis

### Discovery Summary
• **Total Subdomains**: {attack_surface['exposed_services']}
• **Public Endpoints**: {attack_surface['public_ips']}
• **Attack Surface Score**: {attack_surface['score']}/10

### Security Impact
• Exposure Level: **{'High' if attack_surface['score'] > 7 else 'Medium' if attack_surface['score'] > 5 else 'Low'}**
• Risk Level: **{get_risk_level(scan_data)}**
• Infrastructure Grade: {context['metrics']['cyber_hygiene_grade']}

### Key Findings
• Exposed Services: {attack_surface['exposed_services']}
• Open Ports: {attack_surface['open_ports']}
• Public-Facing Assets: {attack_surface['public_ips']}

### Required Actions
1. **Immediate Steps**:
   • Review all exposed subdomains
   • Verify necessary exposure
   • Implement access controls

2. **Security Controls**:
   • Enable DNS monitoring
   • Implement subdomain takeover protection
   • Regular exposure assessments

3. **Monitoring Plan**:
   • Weekly subdomain scans
   • Monthly exposure review
   • Quarterly security assessment
"""

    # Vulnerability Density Analysis
    if any(term in question_lower for term in ['density', 'per asset', 'vulnerability density']):
        # Get total vulnerabilities and assets directly from scan_data
        alerts = scan_data.get('alerts', [])
        total_vulns = len(alerts)  # Use len() instead of accessing 'total_count'
        total_assets = scan_data['attack_surface_index']['metrics']['public_ips']
        
        # Calculate density safely
        density = total_vulns / total_assets if total_assets > 0 else 0
        
        # Get risk counts directly from alerts
        critical_issues = len([a for a in alerts if a.get('risk') == 'Critical'])
        high_issues = len([a for a in alerts if a.get('risk') == 'High'])
        
        return f"""
## Vulnerability Density Analysis

### Current Metrics
• **Vulnerability Density**: {density:.2f} vulnerabilities per asset
• Total Vulnerabilities: {total_vulns}
• Total Assets Scanned: {total_assets}

### Risk Distribution
• Critical Issues: {critical_issues}
• High-Risk Issues: {high_issues}
• Density Risk Level: **{'High' if density > 3 else 'Medium' if density > 1 else 'Low'}**

### Impact Assessment
• Overall Risk Level: **{get_risk_level(scan_data)}**
• Security Grade: {scan_data['cyber_hygiene_score']['grade']}
• Attack Surface Score: {scan_data['attack_surface_index']['score']}/10

### Recommendations
1. **Priority Actions**:
   • {'**Immediate remediation required**' if density > 3 else 'Continue regular patching'}
   • {'Focus on critical vulnerabilities first' if critical_issues > 0 else 'Maintain security posture'}
   • {'Address high-risk issues within 72 hours' if high_issues > 0 else 'Regular monitoring'}

2. **Monitoring Plan**:
   • Daily vulnerability scans
   • Weekly density trend analysis
   • Monthly security assessment
"""

    # Update the scan coverage handler in generate_security_response:

    # Scan Coverage Analysis
    if any(term in question_lower for term in ['coverage', 'scan coverage', 'scan rate']):
        # Get data from endpoints section
        total_endpoints = len(scan_data.get('endpoints', {}).get('endpoints', []))
        total_detected = scan_data['endpoints'].get('total_count', 0)
        coverage_rate = (total_detected / total_endpoints * 100) if total_endpoints > 0 else 0
        
        # Get related metrics
        attack_surface = scan_data['attack_surface_index']
        exposed_services = attack_surface['metrics']['exposed_services_count']
        
        return f"""
## Scan Coverage Analysis

### Current Coverage Metrics
• **Overall Coverage Rate**: {coverage_rate:.1f}%
• Total Endpoints: {total_endpoints}
• Scanned Endpoints: {total_detected}
• Remaining to Scan: {total_endpoints - total_detected}

### Asset Distribution
• Public-Facing Services: {exposed_services}
• Discovered Subdomains: {attack_surface['metrics']['subdomains_count']}
• Public IPs: {attack_surface['metrics']['public_ips_count']}

### Coverage Assessment
• Status: **{'Complete' if coverage_rate >= 95 else 'Partial' if coverage_rate >= 70 else 'Insufficient'}**
• Last Scan: {scan_data['scan_date']}
• Security Grade: {scan_data['cyber_hygiene_score']['grade']}

### Required Actions
1. **Coverage Improvements**:
   • {'Complete scanning of remaining endpoints' if coverage_rate < 80 else 'Maintain current coverage'}
   • {'Prioritize critical systems' if coverage_rate < 70 else 'Regular scan schedule'}
   • Monitor for new endpoints

2. **Monitoring Plan**:
   • Daily coverage tracking
   • Weekly scan validation
   • Monthly coverage reporting

3. **Risk Factors**:
   • Attack Surface Score: {attack_surface['score']}/10
   • Open Ports: {attack_surface['metrics']['open_ports_count']}
   • Exposed Services: {len(attack_surface['metrics']['exposed_services'])}
"""

# Metrics Analysis
    if get_question_type(question) == "metrics" or any(
        term in question_lower for term in 
        ['score', 'hygiene', 'grade', 'rating', 'posture', 'attack surface', 'combined']
    ):
        try:
            metrics = {
                'hygiene_score': scan_data['cyber_hygiene_score']['score'],
                'hygiene_grade': scan_data['cyber_hygiene_score']['grade'],
                'attack_surface': scan_data['attack_surface_index']['score'],
                'combined_score': scan_data['combined_security_score']
            }
            
            return f"""
## Security Metrics Analysis

### Core Security Metrics
• **Cyber Hygiene Score**: {metrics['hygiene_score']}/100
• **Security Grade**: {metrics['hygiene_grade']}
• **Attack Surface Score**: {metrics['attack_surface']}/10
• **Combined Security Score**: {metrics['combined_score']}/100

### Risk Assessment
• Overall Risk Level: **{get_risk_level(scan_data)}**
• Current Status: {'**Action Required**' if metrics['hygiene_score'] < 70 else 'Satisfactory'}
• Exposure Level: {'**High**' if metrics['attack_surface'] > 7 else 'Medium' if metrics['attack_surface'] > 5 else 'Low'}

### Detailed Analysis
• Hygiene Status: {'Critical' if metrics['hygiene_score'] < 60 else 'Warning' if metrics['hygiene_score'] < 80 else 'Good'}
• Attack Surface: {'Excessive' if metrics['attack_surface'] > 8 else 'Moderate' if metrics['attack_surface'] > 5 else 'Minimal'}
• Combined Rating: {'Poor' if metrics['combined_score'] < 60 else 'Fair' if metrics['combined_score'] < 80 else 'Good'}

### Required Actions
1. **Priority Steps**:
   • {'Immediate security review needed' if metrics['hygiene_score'] < 70 else 'Maintain security controls'}
   • {'Reduce attack surface' if metrics['attack_surface'] > 7 else 'Monitor exposure'}
   • {'Address critical findings' if metrics['combined_score'] < 60 else 'Continue improvements'}

2. **Monitoring Plan**:
   • Daily metric tracking
   • Weekly trend analysis
   • Monthly security review
"""
        except KeyError as e:
            logger.error(f"Missing required metric: {e}")
            return "Error: Unable to retrieve complete security metrics. Some data may be missing."

# Add severity mapping for better context
SEVERITY_LEVELS = {
    "3": "Critical",
    "2": "High",
    "1": "Medium",
    "0": "Low"
}

# Add this helper function for detailed recommendations
def get_detailed_recommendations(context: dict, category: str) -> str:
    """Generate detailed recommendations based on category"""
    
    rec_templates = {
        'hygiene': f"""### Detailed Recommendations
1. **Immediate Actions**:
   • {'Conduct emergency security review' if context['metrics']['cyber_hygiene'] < 60 else 'Continue monitoring'}
   • {'Address all critical findings within 24 hours' if context['metrics']['cyber_hygiene'] < 70 else 'Maintain security controls'}
   • {'Schedule urgent security patches' if context['metrics']['cyber_hygiene'] < 80 else 'Follow regular patch schedule'}

2. **Short-term Improvements (1-2 weeks)**:
   • Review and update security configurations
   • Implement missing security controls
   • Conduct thorough vulnerability assessment
   • Update incident response procedures

3. **Long-term Strategy**:
   • Establish continuous monitoring program
   • Implement automated security testing
   • Develop security training program
   • Regular security architecture reviews

4. **Monitoring Requirements**:
   • Daily: Security logs and alerts
   • Weekly: Compliance status checks
   • Monthly: Full security posture review
   • Quarterly: External security audit""",
        
        'owasp': f"""### Detailed Recommendations
1. **Critical Security Fixes** (24-48 hours):
   • Implement missing security headers:
     - X-Frame-Options
     - Content-Security-Policy
     - X-XSS-Protection
   • Address injection vulnerabilities
   • Fix authentication weaknesses
   • Secure sensitive data exposure points

2. **High-Priority Actions** (1 week):
   • Review and update access controls
   • Implement security logging
   • Update security configurations
   • Fix insecure cookie settings

3. **Security Hardening** (2-4 weeks):
   • Conduct security architecture review
   • Implement CSRF protections
   • Update input validation controls
   • Review API security measures

4. **Continuous Improvement**:
   • Weekly vulnerability scans
   • Monthly penetration testing
   • Quarterly security training
   • Regular code security reviews""",
        
        'remediation': f"""### Detailed Recommendations
1. **Critical Issues** (24 hours):
   • Fix authentication vulnerabilities
   • Address injection flaws
   • Patch critical CVEs
   • Resolve data exposure issues

2. **High-Risk Issues** (72 hours):
   • Update security configurations
   • Implement missing controls
   • Fix cross-site scripting issues
   • Address access control gaps

3. **Medium Priority** (1-2 weeks):
   • Review security headers
   • Update SSL/TLS configurations
   • Implement security logging
   • Fix UI redressing issues

4. **Monitoring and Follow-up**:
   • Track remediation progress daily
   • Validate fixes weekly
   • Update security documentation
   • Review incident response plan""",
        
        'infrastructure': f"""### Detailed Recommendations
1. **Network Security** (Immediate):
   • Close unnecessary open ports
   • Review firewall rules
   • Implement network segmentation
   • Secure exposed services

2. **Service Hardening** (48 hours):
   • Update service configurations
   • Implement access controls
   • Enable security logging
   • Review service permissions

3. **Security Controls** (1 week):
   • Deploy WAF protection
   • Implement rate limiting
   • Enable DDoS protection
   • Configure secure protocols

4. **Ongoing Maintenance**:
   • Regular port scans
   • Service inventory updates
   • Configuration reviews
   • Security baseline checks"""
    }
    
    return rec_templates.get(category, """### General Recommendations
1. **Security Basics**:
   • Review security configurations
   • Update security controls
   • Monitor security metrics
   • Maintain documentation

2. **Regular Tasks**:
   • Daily security checks
   • Weekly vulnerability scans
   • Monthly security reviews
   • Quarterly assessments

3. **Long-term Strategy**:
   • Establish security policies
   • Implement training programs
   • Conduct regular audits
   • Develop incident response plans
                             
4. **Monitoring Requirements**:
   • Daily: Security logs and alerts
   • Weekly: Compliance status checks
   • Monthly: Full security posture review
   • Quarterly: External security audit
                    
""")

# Update the recommendations section in your response handlers by adding:
# recommendations = get_detailed_recommendations(context, 'category_name')
# And then include {recommendations} in your f-strings
# ... continue with other response types similarly ...
# Add severity mapping for better context
SEVERITY_LEVELS = {
    "3": "Critical",
    "2": "High",
    "1": "Medium",
    "0": "Low"
}

# Add this at the end of the file
if __name__ == '__main__':
    try:
        logger.info("Starting Flask server...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.critical(f"Failed to start server: {e}")
        raise SystemExit("Server startup failed")
