# syntax=docker/dockerfile:1

# Development image. Vite's dev server provides HMR; a production build would
# use a second stage compiling to static assets served by nginx (see docs).
FROM node:22-alpine

WORKDIR /app

# Install dependencies from the lockfile-aware manifests first so source edits
# do not re-run npm install.
COPY package.json package-lock.json* ./

# `npm ci` requires a lockfile. On the very first build no lockfile exists yet,
# so fall back to `npm install`, which generates one.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . /app

# node:alpine ships an unprivileged `node` user.
RUN chown -R node:node /app
USER node

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
