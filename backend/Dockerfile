FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install curl, gnupg2, and Zeek from OBS
RUN apt-get update && apt-get install -y curl gnupg2 && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' > /etc/apt/sources.list.d/security:zeek.list && \
    apt-get update && apt-get install -y zeek && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Add Zeek to PATH
ENV PATH="/opt/zeek/bin:${PATH}"

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the application port
EXPOSE 8000

# Run the FastAPI application using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
