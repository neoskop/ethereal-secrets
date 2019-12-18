FROM node:12.13.0-buster-slim
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN yarn
COPY src ./src
RUN mkdir -p ./tmp/localstorage && \
    mkdir ./tmp/sessionstorage && \
    yarn build

CMD ["yarn","test"]
EXPOSE 8080 9229
