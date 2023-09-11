FROM node:20.6.1-buster-slim
LABEL maintainer "devops@neoskop.de"

WORKDIR /home/node
COPY *.json ./
RUN chown -R node:node /home/node
USER node
RUN npm i
COPY src ./src
RUN npm run build

CMD ["npm","run","test"]
EXPOSE 8080 9229