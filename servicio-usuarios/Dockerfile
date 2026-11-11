# [V11] Imagen base de Node.js desactualizada (Node 14, fin de soporte en 2023),
# con paquetes del sistema operativo vulnerables.
FROM node:14.17.0-buster-slim

WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --only=production --no-audit --no-fund
COPY src ./src

# [V12] No se define USER: el contenedor se ejecuta como root.
EXPOSE 3001
CMD ["node", "src/server.js"]
