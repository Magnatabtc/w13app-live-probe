FROM node:22-alpine
RUN echo "w13-build-marker $(date -u +%FT%TZ)" > /build-marker.txt
WORKDIR /app
COPY server.js /app/server.js
EXPOSE 3000
CMD ["node","/app/server.js"]
