# Use official Python image
FROM python:3.10-slim-bookworm

# Set the working directory
WORKDIR /app

# Enable bytecode compilation for faster startup
ENV UV_COMPILE_BYTECODE=1

# Install uv
RUN pip install --no-cache-dir uv

# Copy dependency files first (better caching)
COPY pyproject.toml uv.lock ./

# Install dependencies only (no project, no dev)
RUN uv sync --frozen --no-install-project --no-dev

# Copy application code
COPY . .

# Install the project
RUN uv sync --frozen --no-dev

# Ensure virtualenv binaries are first
ENV PATH="/app/.venv/bin:$PATH"

# Run your application
CMD ["python", "app.py"]
