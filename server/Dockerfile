FROM node:12.13.0-buster-slim
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN yarn
COPY src ./src
RUN yarn build

CMD ["yarn","start"]
EXPOSE 8080
