# Playwright's image already has Chromium and all system libraries. Pin a version close to the playwright dep.
FROM mcr.microsoft.com/playwright:v1.49.1-noble

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
