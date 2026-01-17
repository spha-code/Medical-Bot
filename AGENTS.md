# AGENTS.md - Medical Bot Development Guide

This file provides guidelines for AI agents working on this Medical Bot project.

## Build, Lint, and Test Commands

### Installation
```bash
# Install dependencies with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### Running the Application
```bash
# Development mode
python app.py

# With environment variables
FLASK_ENV=development python app.py

# Set required environment variables
export OPENAI_API_KEY="your-key"
export PINECONE_API_KEY="your-key"
```

### Linting and Formatting
```bash
# Run ruff linter (primary tool)
ruff check .

# Auto-fix issues
ruff check --fix .

# Format code
ruff format .

# Type checking with mypy
mypy src/ app.py
```

### Testing
```bash
# Run all tests with pytest
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run a single test file
pytest tests/test_*.py

# Run a single test function
pytest tests/test_api.py::test_health_check

# Run tests matching a pattern
pytest -k "health"

# Run with verbose output
pytest -v
```

## Code Style Guidelines

### Imports
- Group imports in this order: standard library, third-party, local application
- Use absolute imports with `from` syntax
- Sort imports alphabetically within groups
- Maximum line length: 100 characters

### Formatting
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use trailing commas for multi-line structures
- One blank line between top-level definitions
- Two blank lines between class definitions

### Types
- Use type hints for all function parameters and return values
- Prefer explicit types over `Any`
- Use `Optional[X]` instead of `X | None` for compatibility
- Type队伍建设 imports from `typing` module

### Naming Conventions
- **Files**: snake_case (e.g., `medical_bot.py`, `rag_handler.py`)
- **Classes**: PascalCase (e.g., `MedicalAssistant`, `RAGPipeline`)
- **Functions/methods**: snake_case (e.g., `get_medical_response`, `load_documents`)
- **Variables**: snake_case (e.g., `user_query`, `context_window`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_TOKENS`, `DEFAULT_MODEL`)
- **Private members**: Leading underscore (e.g., `_internal_state`)

### Error Handling
- Use specific exceptions (e.g., `ValueError`, `KeyError`, not generic `Exception`)
- Wrap external API calls in try/except with proper logging
- Propagate errors with context: `raise ValueError(f"Failed to load: {filename}") from e`
- Use custom exceptions in `src/exceptions.py` for domain-specific errors
- Log errors before re-raising for audit trail (HIPAA compliance)

### Project Structure
```
medical-bot/
├── app.py              # Flask application entry point
├── src/
│   ├── __init__.py     # Package exports
│   ├── helper.py       # Utility functions
│   └── prompt.py       # RAG prompt templates
├── data/               # Data files (embeddings, docs)
├── tests/              # Test files (create this directory)
├── SECURITY.md         # Security documentation
└── pyproject.toml      # Project configuration
```

### Medical Bot Specific Conventions
- **RAG Pipeline**: Document processing in `src/prompt.py`, vector operations in `src/helper.py`
- **Input Validation**: All user inputs must be sanitized (see `app.py` `InputSanitizer` class)
- **Audit Logging**: Use `log_audit_event()` for all security-relevant operations
- **API Endpoints**: Follow REST patterns, return JSON responses
- **Authentication**: Use `@require_api_key` and `@require_auth` decorators

### Security Requirements
- Never commit `.env` files or API keys
- Use environment variables for all secrets
- Sanitize all user inputs before processing
- Return proper HTTP status codes (400, 401, 403, 429, 500)
- Add rate limiting to all public endpoints
- Include security headers in all responses

### Git Workflow
- Create feature branches: `feature/description` or `fix/issue-description`
- Write meaningful commit messages: "Add input sanitization for medical queries"
- Run linting before committing: `ruff check --fix .`

### Testing Requirements
- Write tests for all new functionality
- Aim for 80%+ code coverage
- Include integration tests for API endpoints
- Mock external APIs (OpenAI, Pinecone) in unit tests
