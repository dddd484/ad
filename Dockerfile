FROM oven/bun:1.3-alpine
WORKDIR /app
COPY index.tsx .
ENV PORT=3000
EXPOSE 3000
CMD ["bun", "run", "index.tsx"]
