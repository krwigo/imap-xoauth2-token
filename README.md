# imap-xoauth2-token

This project is a python socket bridge that allows imap clients to connect, authenticate with delegated service tokens, then continue using imap.

# layout

| file | description |
| --- | --- |
| imap-xoauth2-token.py | main script |
| requirements.txt | python dependencies |
| run.sh | deploy docker container |
| docker-compose.yml | deploy docker service |
| haproxy.cfg.example | example haproxy config |
| service-account.json.example | example service account |
| test.py | verify imap helper |

# deployment

Generate the service password hash:

```bash
echo -n 'password' | sha256sum
```

Configure and deploy a single container:

```bash
docker run --rm -it \
  -v "$(pwd)":/app \
  -w /app \
  -p 143:143 \
  -e GATEWAY_PASSWORD_HASH="your-password-hash" \
  python:3 \
  bash -lc "pip install -r requirements.txt && python imap-xoauth2-token.py"
```

or, configure and deploy a service:

```bash
docker compose -f docker-compose.yml up -d --force-recreate
```

# styles

- No python typing.
- No comments, docstrings, or inline annotations in the source code. Commented-out source blocks are acceptable.
- Merge all standard-library imports onto a single comma-separated line wherever possible (e.g., `import os, sys, re`).
- Combine single-line imports with commas where possible.
- Use f-string formatting (`f"{}"`) instead of `.format()`.
- Clean up empty exception handlers: `except Exception:\n            pass` becomes `except Exception: pass`.

# references

- https://hub.docker.com/_/python
- https://docs.python.org/3/library/imaplib.html
- https://developers.google.com/identity/protocols/oauth2/service-account
- https://developers.google.com/workspace/cloud-search/docs/guides/delegation
