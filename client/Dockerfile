FROM node:24.14.0-bullseye-slim@sha256:89e4f0a8b36b73a32cef97fb2055c040d01af326f4a254588cf081dd794f8124
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
