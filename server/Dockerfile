FROM node:24.14.0-bullseye-slim@sha256:89e4f0a8b36b73a32cef97fb2055c040d01af326f4a254588cf081dd794f8124
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
