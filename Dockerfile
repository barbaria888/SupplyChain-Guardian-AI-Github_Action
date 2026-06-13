FROM python:3.13-alpine

LABEL maintainer="platform-team@example.com"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk update && apk upgrade --no-cache

COPY src/requirements.txt .

RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir --upgrade -r requirements.txt \
    && pip install --no-cache-dir --upgrade starlette==0.40.0

COPY src/ .

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

CMD ["python", "main.py"]