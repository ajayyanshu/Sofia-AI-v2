# 1. Use an official lightweight Python image
FROM python:3.10-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Install Java (required for newer ZAP versions) and tools
RUN apt-get update && \
    apt-get install -y default-jre wget tar && \
    apt-get clean;

# 4. Download and install OWASP ZAP v2.17.0 (Latest Linux version)
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz && \
    tar -xvf ZAP_2.17.0_Linux.tar.gz && \
    mkdir -p /opt/zap && \
    mv ZAP_2.17.0/* /opt/zap/ && \
    rm -rf ZAP_2.17.0 ZAP_2.17.0_Linux.tar.gz && \
    chmod -R 777 /opt/zap

# 5. Copy your requirements file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy all your project files into the container
COPY . .

# 7. Expose the port Flask uses
EXPOSE 5000

# 8. Start the Flask application
CMD ["python", "app.py"]
