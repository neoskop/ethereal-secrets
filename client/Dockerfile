FROM node:21.7.3-bullseye-slim
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

CMD ["npm","run","test"]
EXPOSE 8080 9229
