FROM node:26.8.1-bullseye-slim@sha256:ce69d6017624735163d253581f6bfa3c8bf6c1eb1640ca71393be122c0716838
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN npm i
COPY src ./src
RUN mkdir -p ./tmp/localstorage && \
    mkdir ./tmp/sessionstorage && \
    npm run build

CMD ["npm","start"]
EXPOSE 8080 9229
