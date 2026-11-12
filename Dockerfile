FROM python:3.12-slim

WORKDIR /app

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

COPY pyproject.toml README.md ./
COPY canlix/ canlix/
COPY saas/ saas/

RUN pip install --no-cache-dir ".[saas]"

USER appuser

CMD ["uvicorn", "saas.app:app", "--host", "0.0.0.0", "--port", "8000"]
