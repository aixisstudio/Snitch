# ── Stage 1: Build the React frontend ─────────────────────────────────────────
# EN: Compile the Vite/React app into static files served later by FastAPI.
# FR: Compiler l'application Vite/React en fichiers statiques servis par FastAPI.
FROM node:20-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --prefer-offline
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
# EN: Slim Python image + libpcap (required by Scapy for raw packet capture).
# FR: Image Python légère + libpcap (requise par Scapy pour la capture brute).
FROM python:3.11-slim-bookworm
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# EN: Install Python dependencies first to leverage Docker layer caching.
# FR: Installer les dépendances Python d'abord pour profiter du cache Docker.
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# EN: Backend source code.
# FR: Code source du backend.
COPY backend/ ./backend/

# EN: Compiled React app — served as static files by FastAPI.
# FR: Application React compilée — servie en fichiers statiques par FastAPI.
COPY --from=frontend-builder /build/dist ./frontend_dist/

EXPOSE 8000
WORKDIR /app/backend
CMD ["python", "run_backend.py"]
