FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (ffmpeg for video segmenting, optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .

# Create directory for cat video cache
RUN mkdir -p /var/cat_cache

# Expose port (gunicorn will run on 5000)
EXPOSE 5000

# Run gunicorn
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:5000", "server:app"]
