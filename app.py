from scripts import eml_analyse, osint_toolkit
import streamlit as st

st.set_page_config(
    page_title="CyberToolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

"""
streamlit run app.py --server.port=8501 --server.address=0.0.0.0
"""


# --- Main app structure ---

st.title("CyberToolkit")

tabs = st.tabs(['Email Analyse', 'Reconnaissance'])

# Create the first tab for the "EML Analyser" feature
with tabs[0]:
    st.header("EML Analyser")

    # Instructions
    st.markdown("---")
    st.markdown("## 📖 Instructions")
    st.markdown("""
    1. **Upload an EML file** using the file uploader above
    2. **Configure API keys** in the sidebar for enhanced threat intelligence (optional)
    3. **Review the analysis report** which includes:
       - Email headers and metadata
       - Extracted URLs, IP addresses, and attachments
       - Threat intelligence findings
       - Risk assessment and recommendations
    4. **Download reports** in Markdown or JSON format for further analysis
    
    ### Supported Features:
    - ✅ EML file parsing and metadata extraction
    - ✅ URL and IP address extraction
    - ✅ Attachment analysis with hash computation
    - ✅ Phishing indicator detection
    - ✅ VirusTotal integration (URLs, IPs, file hashes)
    - ✅ AbuseIPDB integration (IP reputation)
    - ✅ Risk scoring and automated reporting
    """)

    # Call the main function from the 'eml_analyse' script.
    # This function contains the logic for the file uploader and analysis.
    eml_analyse.main()

with tabs[1]:
    osint_toolkit.main()