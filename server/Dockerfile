FROM node:16.15.1-buster-slim
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN npm i
COPY src ./src
RUN npm run build

CMD ["npm","start"]
EXPOSE 8080
