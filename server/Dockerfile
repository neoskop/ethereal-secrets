FROM node:26.8.1-bullseye-slim@sha256:ce69d6017624735163d253581f6bfa3c8bf6c1eb1640ca71393be122c0716838
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
