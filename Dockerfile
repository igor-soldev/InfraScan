# InfraScan Unified Docker Image
# This image can run as both a Web App and a CLI tool.
# Usage (Web): docker run -p 5000:5000 soldevelo/infrascan
# Usage (CLI): docker run -v $(pwd):/scan soldevelo/infrascan [cli-args]

FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies including Docker CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and add to docker group
RUN useradd -m appuser && chown -R appuser /app \
    && groupadd -f docker \
    && usermod -aG docker appuser

# Install container vulnerability scanners (both Docker Scout and Grype)
RUN mkdir -p /home/appuser/.local/bin && \
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b /home/appuser/.local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /home/appuser/.local/bin && \
    chown -R appuser:appuser /home/appuser/.local

# Install Python dependencies
COPY --chown=appuser:appuser requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY --chown=appuser:appuser . /app/

# Add local bin to path for appuser
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Prepare entrypoint script
RUN chmod +x /app/entrypoint.sh && chown appuser:appuser /app/entrypoint.sh

# Mount point for user code when running as CLI
VOLUME ["/scan"]

# Default port for web mode
EXPOSE 5000

# Use non-root user for security
USER appuser

# Entrypoint handles switching between web and cli
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command for entrypoint (starts web app)
CMD ["web"]
