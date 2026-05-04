FROM python:3.11-slim

WORKDIR /app

# Install only the required dependency
RUN pip install cryptography

# Copy the client script
COPY client.py .

# The CA certificate will be stored in /app/ca inside the container,
# but we'll mount a volume over it to keep it on the host.

EXPOSE 1080
EXPOSE 8080

CMD ["python", "client.py"]
