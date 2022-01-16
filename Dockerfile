FROM node:14-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci

COPY . .

COPY .env /usr/src/app/.env

COPY .env /usr/share/elasticsearch/data/.env

RUN npm run build