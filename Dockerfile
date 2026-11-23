# AutoChef in a container.
#   docker build -t autochef .
#   docker run --rm -p 127.0.0.1:8471:8471 -v autochef-data:/app/data autochef
# Then open http://127.0.0.1:8471. The server has no login: publish the port on 127.0.0.1 only,
# or put it behind your own authenticating proxy.
FROM node:22-bookworm-slim

ENV NODE_ENV=production HOST=0.0.0.0 PORT=8471
WORKDIR /app

COPY package.json package-lock.json ./
COPY scripts ./scripts
RUN npm ci --ignore-scripts --omit=dev && node scripts/fix-cyberchef.mjs && npm cache clean --force

COPY . .
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
VOLUME ["/app/data"]
EXPOSE 8471
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:8471/api/library').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
