FROM node:24.18.0-bullseye-slim@sha256:aca89821b1f09df223227ff2abe075fc3161f05604d3b61309f46820a5938020
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
