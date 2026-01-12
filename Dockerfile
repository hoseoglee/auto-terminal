# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (e.g. for psutil)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# (FastMCP, psutil, etc.)
# Note: PyQt6 might be heavy/unnecessary for headless MCP, but included if typically required.
# If strictly headless, consider making a separate headless requirements file.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container
COPY . .

# Expose the port used by SSE (default 8000)
EXPOSE 8000

# Run the MCP server
CMD ["python", "gui_launcher.py", "--mcp", "--sse"]
