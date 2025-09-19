# 🛡️ CyberToolkit

A modular security analysis platform that provides security professionals with essential tools through an intuitive web interface. This toolkit combines multiple security analysis capabilities into a single, containerised application.

## **Current Tools**

### Email Analysis

- EML file parsing and investigation
- Header analysis and metadata extraction
- URL/IP threat intelligence integration
- Automated risk scoring and reporting

### OSINT Reconnaissance

- Target information gathering
- Digital footprint analysis
- Threat intelligence correlation

## **🛠️ Technical Implementation**

```python
from scripts import eml_analyse, osint_toolkit
import streamlit as st

st.set_page_config(
    page_title="🛡️ CyberToolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ CyberToolkit")
```

## **🚀 Quick Start**

Open `scripts/eml_analyse.py`
Set your keys on these lines:
```
# Configuration
VIRUSTOTAL_API_KEY = "YOUR_VT_KEY"

ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"
```

Build and run the container:

```
# Build image
docker build -t my-streamlit-app .

# Run container
docker run -p 8501:8501 my-streamlit-app
```

Access the toolkit:

```
http://localhost:8501
```

## **💻 Development Stack**

- Python 3.11
- Streamlit frontend
- Docker containerisation
- VS Code development environment

The toolkit is designed to be modular, allowing easy integration of additional security tools while maintaining a consistent user experience through the Streamlit interface.