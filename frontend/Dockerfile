FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

# Railway exposes service variables to Docker builds through declared ARGs.
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:alpine AS nginx-base
COPY --from=build /app/dist /usr/share/nginx/html

# The nginx image substitutes only PORT, preserving nginx variables such as $host.
ENV PORT=80 \
    NGINX_ENVSUBST_FILTER=PORT
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

# Docker Compose uses the backend service name for same-origin API proxying.
FROM nginx-base AS proxy
COPY nginx.proxy.conf /etc/nginx/templates/default.conf.template

# Railway builds the final target and calls the API's public URL directly.
FROM nginx-base AS runtime
COPY nginx.conf /etc/nginx/templates/default.conf.template
