# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create directories for uploads and output
RUN mkdir -p uploads output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Expose port for web GUI
EXPOSE 5001

# Create a startup script
RUN echo '#!/bin/bash\n\
echo "🚀 Starting Enhanced Asset Classification Tool"\n\
echo "📊 Web GUI will be available at http://localhost:5001"\n\
echo "📁 Upload CSV files and configure scans through the web interface"\n\
echo "🔍 Run ./health_check.sh to verify container health"\n\
python web_gui.py' > /app/start.sh && chmod +x /app/start.sh

# Copy and make health check executable
COPY health_check.sh /app/health_check.sh
RUN chmod +x /app/health_check.sh

# Create non-root user for security (principle of least privilege)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check (using python instead of curl for minimal requirements)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/').read()" || exit 1

# Run the application
CMD ["/app/start.sh"]