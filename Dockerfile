# 1. Use an official lightweight Python image
FROM python:3.10-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Install Java (required for ZAP) and tools to download files
RUN apt-get update && \
    apt-get install -y default-jre wget unzip && \
    apt-get clean;

# 4. Download and install OWASP ZAP 2.14.0
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Crossplatform.zip && \
    unzip ZAP_2.14.0_Crossplatform.zip && \
    mv ZAP_2.14.0 /opt/zap && \
    rm ZAP_2.14.0_Crossplatform.zip

# 5. Copy your requirements file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy all your project files into the container
COPY . .

# 7. Expose the port Flask uses
EXPOSE 5000

# 8. Start the Flask application
CMD ["python", "app.py"]
