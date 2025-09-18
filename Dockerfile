# Use an official Python image as base
FROM python:3.11-slim

# Set work directory inside container
WORKDIR /workspace

# Install system dependencies (you can add more later if your scripts need them)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching efficiency)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files (scripts + streamlit app)
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Default command (can be overridden in devcontainer)
CMD ["bash"]
