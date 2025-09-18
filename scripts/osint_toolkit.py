import streamlit as st
import requests
import re
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Page configuration
st.set_page_config(
    page_title="Recon Toolkit",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

class OSINTRecon:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        
    def get_ip_address(self, domain):
        """Get IP address of domain"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return "Unable to resolve"
    
    def detect_cms(self, url):
        """Detect CMS and technologies"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        cms_signatures = {
            'WordPress': {
                'headers': ['x-pingback'],
                'content': ['/wp-content/', '/wp-includes/', 'wp-json'],
                'meta': ['wordpress', 'wp-'],
                'paths': ['/wp-admin/', '/wp-login.php']
            },
            'Joomla': {
                'headers': [],
                'content': ['/components/com_', '/modules/mod_', 'Joomla!'],
                'meta': ['joomla', 'com_content'],
                'paths': ['/administrator/']
            },
            'Drupal': {
                'headers': ['x-drupal-cache', 'x-generator'],
                'content': ['Drupal.settings', '/sites/default/', '/modules/'],
                'meta': ['drupal'],
                'paths': ['/user/login', '/admin/']
            },
            'Magento': {
                'headers': [],
                'content': ['/skin/frontend/', 'Mage.Cookies', '/js/mage/'],
                'meta': ['magento'],
                'paths': ['/admin/']
            },
            'Shopify': {
                'headers': [],
                'content': ['cdn.shopify.com', 'Shopify.theme', 'shopify'],
                'meta': ['shopify'],
                'paths': ['/admin/']
            }
        }
        
        results = {}
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            for cms, signatures in cms_signatures.items():
                score = 0
                evidence = []
                
                # Check headers
                for header in signatures['headers']:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        score += 30
                        evidence.append(f"Header: {header}")
                
                # Check content
                for pattern in signatures['content']:
                    if pattern.lower() in content:
                        score += 20
                        evidence.append(f"Content: {pattern}")
                
                # Check meta tags
                for meta in signatures['meta']:
                    if re.search(f'name=["\']generator["\'][^>]*{meta}', content, re.I):
                        score += 40
                        evidence.append(f"Meta generator: {meta}")
                
                # Check common paths
                for path in signatures['paths']:
                    try:
                        path_response = self.session.head(urljoin(url, path), timeout=5, verify=False)
                        if path_response.status_code in [200, 301, 302, 403]:
                            score += 25
                            evidence.append(f"Path exists: {path}")
                    except:
                        pass
                
                if score > 0:
                    results[cms] = {
                        'confidence': min(score, 100),
                        'evidence': evidence
                    }
                    
        except Exception as e:
            st.error(f"Error detecting CMS: {str(e)}")
            
        return results
    
    
    def discover_login_portals(self, url):
        """Discover login portals and admin panels"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        common_paths = [
            '/wp-admin/', '/wp-login.php',
            '/admin/', '/admin.php', '/admin/login.php', '/admin/index.php',
            '/administrator/', '/administrator/index.php',
            '/login/', '/login.php', '/login.html',
            '/user/login', '/users/login',
            '/cpanel/', '/webmail/',
            '/phpmyadmin/', '/pma/',
            '/manager/html', '/host-manager/html',
            '/typo3/', '/backend/',
            '/cms/', '/panel/',
            '/control/', '/cp/',
            '/auth/', '/signin/', '/sign-in/',
            '/console/', '/dashboard/'
        ]
        
        portals = []
        
        def check_path(path):
            try:
                full_url = urljoin(url, path)
                response = self.session.head(full_url, timeout=5, allow_redirects=True, verify=False)
                
                if response.status_code in [200, 401, 403]:
                    # Get actual content to verify it's a login page
                    content_response = self.session.get(full_url, timeout=5, verify=False)
                    content = content_response.text.lower()
                    
                    login_indicators = ['login', 'password', 'username', 'sign in', 'log in', 'authentication']
                    if any(indicator in content for indicator in login_indicators):
                        return {
                            'path': path,
                            'url': full_url,
                            'status': response.status_code,
                            'title': self.extract_title(content_response.text)
                        }
            except:
                pass
            return None
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_path, common_paths))
        
        portals = [result for result in results if result is not None]
        
        return portals
    
    def extract_title(self, html):
        """Extract title from HTML"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if title_match:
            return title_match.group(1).strip()
        return "No title"
    
    def generate_html_report(self, target_info, cms_results, users, portals, analyst_name):
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OSINT Reconnaissance Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                    line-height: 1.6;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    margin: -30px -30px 30px -30px;
                    border-radius: 10px 10px 0 0;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                    text-align: center;
                }}
                .section {{
                    margin: 30px 0;
                    padding: 20px;
                    border-left: 4px solid #667eea;
                    background-color: #f8f9fa;
                }}
                .section h2 {{
                    color: #333;
                    border-bottom: 2px solid #667eea;
                    padding-bottom: 10px;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .info-card {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    border: 1px solid #ddd;
                }}
                .cms-result {{
                    background: white;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 8px;
                    border-left: 4px solid #28a745;
                }}
                .confidence {{
                    display: inline-block;
                    padding: 5px 10px;
                    background-color: #28a745;
                    color: white;
                    border-radius: 15px;
                    font-size: 0.9em;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 15px 0;
                    background: white;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #667eea;
                    color: white;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #666;
                }}
                .evidence {{
                    font-size: 0.9em;
                    color: #666;
                    margin-top: 10px;
                }}
                .portal-link {{
                    color: #667eea;
                    text-decoration: none;
                }}
                .portal-link:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 OSINT Reconnaissance Report</h1>
                </div>
                
                <div class="section">
                    <h2>📋 Target Information</h2>
                    <div class="info-grid">
                        <div class="info-card">
                            <h4>🎯 Target Domain</h4>
                            <p><strong>{target_info['domain']}</strong></p>
                        </div>
                        <div class="info-card">
                            <h4>🌐 IP Address</h4>
                            <p>{target_info['ip']}</p>
                        </div>
                        <div class="info-card">
                            <h4>📅 Scan Date</h4>
                            <p>{timestamp}</p>
                        </div>
                        <div class="info-card">
                            <h4>👤 Analyst</h4>
                            <p>{analyst_name}</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>⚙️ CMS Detection Results</h2>
        """
        
        if cms_results:
            for cms, details in cms_results.items():
                html_template += f"""
                    <div class="cms-result">
                        <h4>{cms} <span class="confidence">{details['confidence']}% confidence</span></h4>
                        <div class="evidence">
                            <strong>Evidence found:</strong>
                            <ul>
                """
                for evidence in details['evidence']:
                    html_template += f"<li>{evidence}</li>"
                html_template += "</ul></div></div>"
        else:
            html_template += "<p>No CMS detected or unable to determine CMS type.</p>"
        
        html_template += """
                </div>
                
                <div class="section">
                    <h2>👥 Discovered Users</h2>
        """
        
        if users:
            html_template += """
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Display Name</th>
                                <th>Discovery Method</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for user in users:
                html_template += f"""
                            <tr>
                                <td>{user.get('id', 'N/A')}</td>
                                <td><strong>{user.get('username', 'N/A')}</strong></td>
                                <td>{user.get('display_name', 'N/A')}</td>
                                <td>{user.get('method', 'N/A')}</td>
                            </tr>
                """
            html_template += "</tbody></table>"
        else:
            html_template += "<p>No users discovered.</p>"
        
        html_template += """
                </div>
                
                <div class="section">
                    <h2>🔐 Login Portals Discovered</h2>
        """
        
        if portals:
            html_template += """
                    <table>
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Full URL</th>
                                <th>Status</th>
                                <th>Page Title</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for portal in portals:
                html_template += f"""
                            <tr>
                                <td><strong>{portal['path']}</strong></td>
                                <td><a href="{portal['url']}" class="portal-link" target="_blank">{portal['url']}</a></td>
                                <td>{portal['status']}</td>
                                <td>{portal['title']}</td>
                            </tr>
                """
            html_template += "</tbody></table>"
        else:
            html_template += "<p>No login portals discovered.</p>"
        
        html_template += f"""
                </div>
                
                <div class="footer">
                    <p>Report generated by OSINT Recon Toolkit on {timestamp}</p>
                    <p>Analyst: {analyst_name}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_template

def main():
    # Welcome screen
    st.title("🔍 Reconnaissance")
    st.markdown("**This toolkit provides comprehensive reconnaissance capabilities including**")

    col1, col2 = st.columns(2)

    with col1:
        st.header("⚙️ CMS Detection")
        st.markdown("""
            - Automatically detect content management systems
            - Support for WordPress, Joomla, Drupal, Magento, Shopify
            - Confidence scoring and evidence collection
        """)

    with col2:
        st.header("🔐 **Login Portal Discovery**")
        st.markdown("""
            - Comprehensive admin panel discovery
            - Common path enumeration
            - Authentication page detection
        """)

    col1, col2 = st.columns(2)
    
    with col1:
        st.header("🔐 **Professional Reporting**")
        st.markdown("""
            - Clean HTML report generation
            - Structured findings presentation
            - Exportable results
        """)

    # Initialize OSINT class
    if 'osint' not in st.session_state:
        st.session_state.osint = OSINTRecon()
    
    # Initialize session state
    if 'target_info' not in st.session_state:
        st.session_state.target_info = {}
    if 'cms_results' not in st.session_state:
        st.session_state.cms_results = {}
    if 'users' not in st.session_state:
        st.session_state.users = []
    if 'portals' not in st.session_state:
        st.session_state.portals = []
    
    # Sidebar
    with st.container():
        st.subheader("🎯 Target Configuration")
        target_domain = st.text_input("Target Domain", placeholder="example.com")
        analyst_name = st.text_input("Analyst Name", placeholder="Your Name")
        
        st.header("🛠️ Scan Options")
        scan_cms = st.checkbox("CMS Detection", value=True)
        scan_users = st.checkbox("User Enumeration", value=True)
        scan_portals = st.checkbox("Login Portal Discovery", value=True)
        
        if st.button("🚀 Start Reconnaissance", type="primary", use_container_width=True):
            if target_domain:
                # Clear previous results
                st.session_state.target_info = {}
                st.session_state.cms_results = {}
                st.session_state.users = []
                st.session_state.portals = []
                
                # Store target info
                st.session_state.target_info = {
                    'domain': target_domain,
                    'ip': st.session_state.osint.get_ip_address(target_domain),
                    'analyst': analyst_name or "Anonymous"
                }
                
                st.rerun()
            else:
                st.error("Please enter a target domain")
    
    # Main content area
    if st.session_state.target_info:
        domain = st.session_state.target_info['domain']
        
        # Target Information
        st.header("📋 Target Information")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🎯 Domain", domain)
        with col2:
            st.metric("🌐 IP Address", st.session_state.target_info['ip'])
        with col3:
            st.metric("📅 Scan Time", datetime.now().strftime("%H:%M:%S"))
        with col4:
            st.metric("👤 Analyst", st.session_state.target_info['analyst'])
        
        # Create tabs for different scan results
        tabs = st.tabs(["⚙️ CMS Detection", "🔐 Login Portals", "📄 Report"])
        
        with tabs[0]:
            st.header("⚙️ CMS Detection")
            
            if scan_cms:
                if not st.session_state.cms_results:
                    with st.spinner("Detecting CMS..."):
                        st.session_state.cms_results = st.session_state.osint.detect_cms(domain)
                
                if st.session_state.cms_results:
                    for cms, details in st.session_state.cms_results.items():
                        with st.expander(f"**{cms}** - {details['confidence']}% confidence", expanded=True):
                            st.write("**Evidence found:**")
                            for evidence in details['evidence']:
                                st.write(f"• {evidence}")
                else:
                    st.info("No CMS detected or unable to determine CMS type")
            else:
                st.info("CMS detection disabled in scan options")
        
        
        with tabs[1]:
            st.header("🔐 Login Portal Discovery")
            
            if scan_portals:
                if not st.session_state.portals:
                    with st.spinner("Discovering login portals..."):
                        st.session_state.portals = st.session_state.osint.discover_login_portals(domain)
                
                if st.session_state.portals:
                    for portal in st.session_state.portals:
                        with st.container():
                            col1, col2, col3, col4 = st.columns([2, 3, 1, 2])
                            with col1:
                                st.write(f"**{portal['path']}**")
                            with col2:
                                st.link_button("🔗 Open", portal['url'])
                            with col3:
                                st.badge(f"HTTP {portal['status']}")
                            with col4:
                                st.write(portal['title'][:30] + "..." if len(portal['title']) > 30 else portal['title'])
                else:
                    st.info("No login portals discovered")
            else:
                st.info("Login portal discovery disabled in scan options")
        
        with tabs[2]:
            st.header("📄 Generate Report")
            
            if st.button("📋 Generate HTML Report", type="primary", use_container_width=True):
                if any([st.session_state.cms_results, st.session_state.users, st.session_state.portals]):
                    html_report = st.session_state.osint.generate_html_report(
                        st.session_state.target_info,
                        st.session_state.cms_results,
                        st.session_state.users,
                        st.session_state.portals,
                        analyst_name or "Anonymous"
                    )
                    
                    # Create download button
                    st.download_button(
                        label="📥 Download HTML Report",
                        data=html_report,
                        file_name=f"{domain}_osint_report.html",
                        mime="text/html"
                    )
                    
                    st.success("Report generated successfully!")
                    
                    # Show preview
                    with st.expander("Preview Report"):
                        st.components.v1.html(html_report, height=600, scrolling=True)
                else:
                    st.warning("No data available to generate report. Please run some scans first.")
    
    else:
        # Show some statistics or recent scans
        with st.container():
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("🎯 Domains Scanned", "0")
            with col2:
                st.metric("⚙️ CMS Detected", "0")
            with col3:
                st.metric("🔐 Portals Discovered", "0")

if __name__ == "__main__":
    main()