FROM node:24.19.0-bullseye-slim@sha256:7af27dbbe7d3e4512b83a49b8831463d5cbfdd2dce22675af73558f5ad66e8ef
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