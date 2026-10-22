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
# EN: Slim Python image + libpcap — the capture engine is a ctypes binding
#     (capture/pcap.py), so libpcap0.8 is the only native dependency needed.
# FR: Image Python légère + libpcap — le moteur de capture est une liaison
#     ctypes (capture/pcap.py), donc libpcap0.8 est la seule dépendance native.
FROM python:3.11-slim-bookworm
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
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

# EN: No USER directive — the container intentionally runs as root because
#     libpcap needs CAP_NET_RAW/CAP_NET_ADMIN to capture. Compose grants only
#     those two caps; do NOT add a USER here or capture silently stops.
# FR: Pas de directive USER — le conteneur tourne volontairement en root car
#     libpcap exige CAP_NET_RAW/CAP_NET_ADMIN pour capturer. Compose n'accorde
#     que ces deux capacités ; ne PAS ajouter de USER, la capture s'arrêterait.
EXPOSE 8000
WORKDIR /app/backend
CMD ["python", "run_backend.py"]
