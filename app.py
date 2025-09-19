from scripts import eml_analyse, osint_toolkit
import streamlit as st

st.set_page_config(
    page_title="CyberToolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Main app structure ---

st.title("CyberToolkit")

tabs = st.tabs(['Email Analyse', 'Reconnaissance'])

# Create the first tab for the "EML Analyser" feature
with tabs[0]:
    eml_analyse.main()

with tabs[1]:
    osint_toolkit.main()