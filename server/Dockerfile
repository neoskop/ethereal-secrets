FROM node:24.19.0-bullseye-slim@sha256:fe7ca92ba828017e16f6afb41f4cf7fc5ec7adecf8246825800ac102e30906f3
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node/app
COPY middleware ./middleware
COPY server/package*.json ./server/
RUN chown -R node:node /home/node/app
USER node
RUN npm install ./middleware && npm run build --prefix ./middleware
WORKDIR /home/node/app/server
RUN npm install
COPY server/index.js .

EXPOSE 8080
CMD ["npm","run","start"]
