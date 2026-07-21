FROM node:24.18.0-bullseye-slim@sha256:aca89821b1f09df223227ff2abe075fc3161f05604d3b61309f46820a5938020
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