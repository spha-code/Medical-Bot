# Use the official uv image for the build stage
FROM ghcr.io/astral-sh/uv:python3.10-slim-bookworm

# Set the working directory
WORKDIR /app

# Enable bytecode compilation for faster startup
ENV UV_COMPILE_BYTECODE=1

# Copy only the dependency files first (optimizes Docker caching)
COPY pyproject.toml uv.lock ./

# Install dependencies without installing the project itself
# --frozen ensures the lockfile isn't updated during build
RUN uv sync --frozen --no-install-project --no-dev

# Copy the rest of your application code
COPY . .

# Install the project
RUN uv sync --frozen --no-dev

# Place /app/.venv/bin at the beginning of the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Run your application
CMD ["python", "app.py"]