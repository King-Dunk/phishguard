FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn pydantic anthropic
COPY phishguard ./phishguard
RUN useradd --create-home --uid 10001 app
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "phishguard.api:get_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
