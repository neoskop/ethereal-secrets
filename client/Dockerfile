FROM node:24.19.0-bullseye-slim@sha256:fe7ca92ba828017e16f6afb41f4cf7fc5ec7adecf8246825800ac102e30906f3
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
