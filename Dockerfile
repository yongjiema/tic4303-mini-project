FROM docker.io/node:lts AS builder

WORKDIR /app

COPY . .

RUN npm install \
    && npm run build


# Security: Use a minimal base image to reduce the attack surface
FROM docker.io/node:lts-slim
RUN userdel -r node


ENV DATABASE_PATH=/data/database.sqlite

WORKDIR /app

# Security: Use multi-stage build to copy only necessary files, excluding build tools and dependencies
COPY --from=builder /app .

# Security: Install only production dependencies to reduce potential vulnerabilities
RUN rm -rf node_modules \
    && npm install --only=production

RUN mkdir /data

# Security: Create a non-root user and run the container as a non-root user to limit permissions
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 -g appgroup -s /bin/false -m appuser \
    && chown -R appuser:appgroup /data
USER appuser

VOLUME /data
EXPOSE 3000

CMD ["node", "src/app.js"]
