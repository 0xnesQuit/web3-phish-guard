# Playwright's image already has Chromium and all system libraries. Pin a version close to the playwright dep.
FROM mcr.microsoft.com/playwright:v1.49.1-noble

# Security patch: the base image ships Node 22.12.0, but the October 2026 CVEs (Brotli OOB-write RCE, TLS hostname
# bypass, eMudhra CA distrust) need 22.23.4+. Upgrade to the latest patched 22.x and refresh the system CA store.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && node -v

WORKDIR /app

COPY package.json package-lock.json* ./
# full install (incl. dev deps: typescript + @types) so the build can run; --ignore-scripts skips the browser download (the base image already has Chromium)
RUN npm ci --ignore-scripts || npm install --ignore-scripts

COPY tsconfig.json ./
COPY src ./src
# compile TypeScript, then drop dev deps from the runtime image
RUN npx tsc -p tsconfig.json && npm prune --omit=dev

ENV NODE_ENV=production
EXPOSE 8080
# SANDBOX_TOKEN must be provided at runtime: docker run -e SANDBOX_TOKEN=...  -p 8080:8080 image
CMD ["node", "dist/server.js"]
