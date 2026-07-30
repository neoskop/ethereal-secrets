FROM node:24.18.1-bullseye-slim@sha256:0527cf34f5753822dd7b0e6fd84cc2e81d9d10d60bed88af4dd7efb870317c6b
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN npm i
COPY src ./src
RUN npm run build

CMD ["npm","start"]
EXPOSE 8080 9229