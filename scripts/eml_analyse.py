import streamlit as st
import email
import email.policy
import re
import hashlib
import json
import requests
from datetime import datetime
from typing import Dict
import base64
from urllib.parse import urlparse
import time

# Configuration
VIRUSTOTAL_API_KEY = ""  # Add your VirusTotal API key
ABUSEIPDB_API_KEY = ""   # Add your AbuseIPDB API key

class EmailInvestigator:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "headers": {},
            "urls": [],
            "ip_addresses": [],
            "attachments": [],
            "threat_intelligence": {},
            "risk_score": 0,
            "phishing_indicators": [],
            "summary": ""
        }
    
    def parse_eml(self, eml_content: str) -> Dict:
        """Phase 1: Parse EML file and extract critical information"""
        try:
            # Parse email content
            msg = email.message_from_string(eml_content, policy=email.policy.default)
            
            # Extract headers
            self.results["headers"] = {
                "from": msg.get("From", ""),
                "to": msg.get("To", ""),
                "subject": msg.get("Subject", ""),
                "date": msg.get("Date", ""),
                "reply_to": msg.get("Reply-To", ""),
                "return_path": msg.get("Return-Path", ""),
                "received": msg.get_all("Received", [])
            }
            
            # Extract email body
            body_text = ""
            body_html = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body_text += part.get_content()
                    elif content_type == "text/html":
                        body_html += part.get_content()
                    elif part.get_filename():
                        self._extract_attachment(part)
            else:
                content_type = msg.get_content_type()
                if content_type == "text/plain":
                    body_text = msg.get_content()
                elif content_type == "text/html":
                    body_html = msg.get_content()
            
            # Extract URLs and IPs from body
            full_body = body_text + " " + body_html
            self._extract_urls(full_body)
            self._extract_ips(full_body)
            self._extract_urls_from_headers()
            
            # Check for phishing indicators
            self._check_phishing_indicators()
            
            return self.results
            
        except Exception as e:
            st.error(f"Error parsing EML: {str(e)}")
            return {}
    
    def _extract_attachment(self, part):
        """Extract attachment information and compute hash"""
        filename = part.get_filename()
        if filename:
            content = part.get_payload(decode=True)
            if content:
                file_hash = hashlib.sha256(content).hexdigest()
                file_size = len(content)
                file_extension = filename.split('.')[-1].lower() if '.' in filename else ''
                
                attachment_info = {
                    "filename": filename,
                    "size": file_size,
                    "extension": file_extension,
                    "sha256": file_hash,
                    "content_type": part.get_content_type()
                }
                
                self.results["attachments"].append(attachment_info)
    
    def _extract_urls(self, text: str):
        """Extract URLs using regex"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            if parsed.netloc and url not in [u["url"] for u in self.results["urls"]]:
                self.results["urls"].append({
                    "url": url,
                    "domain": parsed.netloc,
                    "path": parsed.path
                })
    
    def _extract_ips(self, text: str):
        """Extract IP addresses using regex"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        for ip in ips:
            if self._is_valid_ip(ip) and ip not in self.results["ip_addresses"]:
                self.results["ip_addresses"].append(ip)
    
    def _extract_urls_from_headers(self):
        """Extract URLs from email headers"""
        header_text = " ".join([str(v) for v in self.results["headers"].values() if v])
        self._extract_urls(header_text)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format and exclude private ranges"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            nums = [int(part) for part in parts]
            if not all(0 <= num <= 255 for num in nums):
                return False
            
            # Exclude private IP ranges
            if (nums[0] == 10 or 
                (nums[0] == 172 and 16 <= nums[1] <= 31) or
                (nums[0] == 192 and nums[1] == 168) or
                nums[0] == 127):
                return False
            
            return True
        except ValueError:
            return False
    
    def _check_phishing_indicators(self):
        """Check for common phishing indicators"""
        indicators = []
        
        # Check for mismatched Reply-To
        from_addr = self.results["headers"].get("from", "")
        reply_to = self.results["headers"].get("reply_to", "")
        
        if reply_to and from_addr:
            from_domain = from_addr.split('@')[-1].strip('>')
            reply_domain = reply_to.split('@')[-1].strip('>')
            if from_domain != reply_domain:
                indicators.append("Mismatched Reply-To domain")
        
        # Check for suspicious subject patterns
        subject = self.results["headers"].get("subject", "").lower()
        suspicious_keywords = ['urgent', 'verify', 'suspended', 'click here', 'act now', 'limited time']
        for keyword in suspicious_keywords:
            if keyword in subject:
                indicators.append(f"Suspicious subject keyword: {keyword}")
        
        # Check for URL shorteners
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        for url_info in self.results["urls"]:
            if any(shortener in url_info["domain"] for shortener in url_shorteners):
                indicators.append(f"URL shortener detected: {url_info['domain']}")
        
        self.results["phishing_indicators"] = indicators
    
    def enrich_with_threat_intelligence(self):
        """Phase 2: Enrich data with threat intelligence"""
        ti_results = {
            "urls": {},
            "ips": {},
            "hashes": {}
        }
        
        # Check URLs with VirusTotal
        for url_info in self.results["urls"]:
            if VIRUSTOTAL_API_KEY:
                vt_result = self._check_url_virustotal(url_info["url"])
                ti_results["urls"][url_info["url"]] = vt_result
                time.sleep(1)  # Rate limiting
        
        # Check IPs with AbuseIPDB
        for ip in self.results["ip_addresses"]:
            if ABUSEIPDB_API_KEY:
                abuse_result = self._check_ip_abuseipdb(ip)
                ti_results["ips"][ip] = abuse_result
                time.sleep(1)  # Rate limiting
        
        # Check attachment hashes with VirusTotal
        for attachment in self.results["attachments"]:
            if VIRUSTOTAL_API_KEY:
                vt_result = self._check_hash_virustotal(attachment["sha256"])
                ti_results["hashes"][attachment["sha256"]] = vt_result
                time.sleep(1)  # Rate limiting
        
        self.results["threat_intelligence"] = ti_results
        self._calculate_risk_score()
    
    def _check_url_virustotal(self, url: str) -> Dict:
        """Check URL reputation with VirusTotal"""
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "total_scans": sum(stats.values()) if stats else 0
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_ip_abuseipdb(self, ip: str) -> Dict:
        """Check IP reputation with AbuseIPDB"""
        try:
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence": data.get("abuseConfidencePercentage", 0),
                    "is_malicious": data.get("abuseConfidencePercentage", 0) > 50,
                    "country": data.get("countryCode", ""),
                    "total_reports": data.get("totalReports", 0)
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_hash_virustotal(self, file_hash: str) -> Dict:
        """Check file hash with VirusTotal"""
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "total_scans": sum(stats.values()) if stats else 0
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def _calculate_risk_score(self):
        """Calculate overall risk score"""
        score = 0
        
        # Phishing indicators
        score += len(self.results["phishing_indicators"]) * 10
        
        # Threat intelligence results
        ti = self.results["threat_intelligence"]
        
        # URLs
        for url_result in ti["urls"].values():
            if not isinstance(url_result, dict) or "error" in url_result:
                continue
            malicious = url_result.get("malicious", 0)
            suspicious = url_result.get("suspicious", 0)
            score += malicious * 20 + suspicious * 10
        
        # IPs
        for ip_result in ti["ips"].values():
            if not isinstance(ip_result, dict) or "error" in ip_result:
                continue
            if ip_result.get("is_malicious", False):
                score += 30
            score += ip_result.get("abuse_confidence", 0) // 10
        
        # Hashes
        for hash_result in ti["hashes"].values():
            if not isinstance(hash_result, dict) or "error" in hash_result:
                continue
            malicious = hash_result.get("malicious", 0)
            suspicious = hash_result.get("suspicious", 0)
            score += malicious * 25 + suspicious * 15
        
        self.results["risk_score"] = min(score, 100)  # Cap at 100
    
    def generate_report(self) -> str:
        """Phase 3: Generate comprehensive report"""
        report = []
        report.append("# SOC Email Investigation Report")
        report.append(f"**Generated:** {self.results['timestamp']}")
        report.append(f"**Risk Score:** {self.results['risk_score']}/100")
        
        # Risk level
        if self.results['risk_score'] >= 70:
            risk_level = "🔴 HIGH RISK"
        elif self.results['risk_score'] >= 40:
            risk_level = "🟡 MEDIUM RISK"
        else:
            risk_level = "🟢 LOW RISK"
        
        report.append(f"**Risk Level:** {risk_level}")
        report.append("")
        
        # Email headers
        report.append("## Email Headers")
        headers = self.results["headers"]
        report.append(f"- **From:** {headers.get('from', 'N/A')}")
        report.append(f"- **To:** {headers.get('to', 'N/A')}")
        report.append(f"- **Subject:** {headers.get('subject', 'N/A')}")
        report.append(f"- **Date:** {headers.get('date', 'N/A')}")
        if headers.get('reply_to'):
            report.append(f"- **Reply-To:** {headers.get('reply_to')}")
        report.append("")
        
        # Phishing indicators
        if self.results["phishing_indicators"]:
            report.append("## ⚠️ Phishing Indicators")
            for indicator in self.results["phishing_indicators"]:
                report.append(f"- {indicator}")
            report.append("")
        
        # URLs
        if self.results["urls"]:
            report.append("## URLs Found")
            for url_info in self.results["urls"]:
                url = url_info["url"]
                report.append(f"- **URL:** {url}")
                report.append(f"  - **Domain:** {url_info['domain']}")
                
                if url in self.results["threat_intelligence"]["urls"]:
                    ti_data = self.results["threat_intelligence"]["urls"][url]
                    if "error" not in ti_data:
                        mal = ti_data.get("malicious", 0)
                        sus = ti_data.get("suspicious", 0)
                        report.append(f"  - **VirusTotal:** {mal} malicious, {sus} suspicious")
                report.append("")
        
        # IP addresses
        if self.results["ip_addresses"]:
            report.append("## IP Addresses Found")
            for ip in self.results["ip_addresses"]:
                report.append(f"- **IP:** {ip}")
                
                if ip in self.results["threat_intelligence"]["ips"]:
                    ti_data = self.results["threat_intelligence"]["ips"][ip]
                    if "error" not in ti_data:
                        confidence = ti_data.get("abuse_confidence", 0)
                        country = ti_data.get("country", "Unknown")
                        report.append(f"  - **AbuseIPDB:** {confidence}% confidence, Country: {country}")
                report.append("")
        
        # Attachments
        if self.results["attachments"]:
            report.append("## Attachments Found")
            for attachment in self.results["attachments"]:
                report.append(f"- **Filename:** {attachment['filename']}")
                report.append(f"  - **Size:** {attachment['size']} bytes")
                report.append(f"  - **SHA256:** {attachment['sha256']}")
                
                if attachment['sha256'] in self.results["threat_intelligence"]["hashes"]:
                    ti_data = self.results["threat_intelligence"]["hashes"][attachment['sha256']]
                    if "error" not in ti_data:
                        mal = ti_data.get("malicious", 0)
                        sus = ti_data.get("suspicious", 0)
                        report.append(f"  - **VirusTotal:** {mal} malicious, {sus} suspicious")
                report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        if self.results['risk_score'] >= 70:
            report.append("- **IMMEDIATE ACTION REQUIRED**")
            report.append("- Block sender and quarantine email")
            report.append("- Notify users about potential threat")
            report.append("- Investigate any clicked links or opened attachments")
        elif self.results['risk_score'] >= 40:
            report.append("- Monitor for similar emails")
            report.append("- Consider additional verification of sender")
            report.append("- Review security awareness training")
        else:
            report.append("- Email appears legitimate based on current analysis")
            report.append("- Continue standard monitoring")
        
        return "\n".join(report)
    
    
# Streamlit App
def main():
    st.header("EML Analyser")

    col1, col2 = st.columns(2)

    with col1:
        st.header("📖 Instructions")
        st.markdown("""
            1. **Upload an EML file** using the file uploader above
            2. **Configure API keys** in the sidebar for enhanced threat intelligence (optional)
            3. **Review the analysis report** which includes:
                - Email headers and metadata
                - Extracted URLs, IP addresses, and attachments
                - Threat intelligence findings
                - Risk assessment and recommendations
            4. **Download reports** in Markdown or JSON format for further analysis
        """)

    with col2:
        st.header("Supported Features")
        st.markdown("""
            - ✅ EML file parsing and metadata extraction
            - ✅ URL and IP address extraction
            - ✅ Attachment analysis with hash computation
            - ✅ Phishing indicator detection
            - ✅ VirusTotal integration (URLs, IPs, file hashes)
            - ✅ AbuseIPDB integration (IP reputation)
            - ✅ Risk scoring and automated reporting
        """)
    
    # 🔥 ADD THE DETAILED VALIDATION SECTION HERE
    api_warnings = []
    
    if not VIRUSTOTAL_API_KEY:
        api_warnings.append("🔑 **VirusTotal API Key missing**")

    if not ABUSEIPDB_API_KEY:
        api_warnings.append("🔑 **AbuseIPDB API Key missing**")

    if api_warnings:
        st.warning("⚠️ **API Configuration Issues**")

        col1, col2 = st.columns(2)
        for i, warning in enumerate(api_warnings):
            if i == 0:
                with col1:
                    st.markdown(warning)
            elif i == 1:
                with col2:
                    st.markdown(warning)
    else:
    
        # File upload
        uploaded_file = st.file_uploader(
            "Choose an EML file",
            type=['eml'],
            help="Upload an .eml file for analysis"
        )
    
        if uploaded_file is not None:
            # Read the file content
            eml_content = uploaded_file.read().decode('utf-8', errors='ignore')
            
            # Create investigator instance
            investigator = EmailInvestigator()
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Phase 1: Parsing
            status_text.text("Phase 1: Parsing EML file...")
            progress_bar.progress(25)
            
            results = investigator.parse_eml(eml_content)
            
            if results:
                # Phase 2: Threat Intelligence (if API keys provided)
                if VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY:
                    status_text.text("Phase 2: Enriching with threat intelligence...")
                    progress_bar.progress(50)
                    investigator.enrich_with_threat_intelligence()
                    progress_bar.progress(75)
                else:
                    progress_bar.progress(75)
                
                # Phase 3: Generate report
                status_text.text("Phase 3: Generating report...")
                progress_bar.progress(100)
                
                report = investigator.generate_report()
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Display results
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown("## 📊 Analysis Report")
                    st.markdown(report)
                
                with col2:
                    st.markdown("## 📈 Quick Stats")
                    
                    # Risk score meter
                    risk_score = results.get('risk_score', 0)
                    if risk_score >= 70:
                        color = "red"
                    elif risk_score >= 40:
                        color = "orange"
                    else:
                        color = "green"
                    
                    st.metric("Risk Score", f"{risk_score}/100")
                    st.markdown(f'<div style="background-color: {color}; height: 10px; width: {risk_score}%; border-radius: 5px;"></div>', unsafe_allow_html=True)
                    
                    # Statistics
                    st.metric("URLs Found", len(results.get('urls', [])))
                    st.metric("IP Addresses", len(results.get('ip_addresses', [])))
                    st.metric("Attachments", len(results.get('attachments', [])))
                    st.metric("Phishing Indicators", len(results.get('phishing_indicators', [])))
                    
                    # Download report
                    st.download_button(
                        label="📄 Download Report",
                        data=report,
                        file_name=f"email_investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
                    
                    # Download JSON data
                    st.download_button(
                        label="📋 Download JSON Data",
                        data=json.dumps(results, indent=2),
                        file_name=f"email_investigation_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
    
    

if __name__ == "__main__":
    main()
