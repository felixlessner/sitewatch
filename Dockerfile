FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 appuser && chown -R appuser:appuser /app
USER appuser
CMD ["sh", "-c", "exec gunicorn -w 2 -b 0.0.0.0:${PORT:-10000} --timeout 40 app:application"]