# syntax=docker/dockerfile:1

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup
USER appuser
EXPOSE 3000
# --proxy-headers makes uvicorn trust X-Forwarded-For from the proxy in front
# of it, so per-client rate limiting keys on the real client IP instead of the
# proxy's. Set FORWARDED_ALLOW_IPS to the proxy's IP/CIDR in production.
# Shell-form CMD so ${PORT} expands: Cloud Run injects PORT and expects the
# container to listen on it; locally PORT is unset and we default to 3000.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-3000} --proxy-headers
