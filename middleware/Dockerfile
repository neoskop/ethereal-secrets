FROM node:12.13.0-buster-slim AS build
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json yarn.lock ./
RUN chown -R node:node /home/node
USER node
RUN yarn
COPY src ./src
RUN yarn build

CMD ["yarn","test"]
EXPOSE 8080 9229