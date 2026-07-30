FROM node:24.18.1-bullseye-slim@sha256:0527cf34f5753822dd7b0e6fd84cc2e81d9d10d60bed88af4dd7efb870317c6b
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
