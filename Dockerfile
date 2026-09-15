FROM node:22-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public
COPY .env.example ./.env

EXPOSE 3000
CMD ["npm", "start"]
