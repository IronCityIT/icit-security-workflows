FROM python:3.9-slim

WORKDIR /app

RUN pip install --no-cache-dir threatingestor

# Create output directory
RUN mkdir -p /app/output

# Default command
CMD ["threatingestor", "/app/config.yml"]
