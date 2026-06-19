#!/usr/bin/env bash
docker run --rm -it \
  -v "$(pwd)":/app \
  -w /app \
  -p 143:143 \
  -e GATEWAY_PASSWORD_HASH="your-password-hash" \
  python:3 \
  bash -lc "pip install -r requirements.txt && python imap-xoauth2-token.py"
