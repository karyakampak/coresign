FROM ubuntu:latest

# Set environment variables to prevent some issues with Debian frontend
ENV DEBIAN_FRONTEND=noninteractive

USER root

WORKDIR /var/www/html

RUN apt-get update && apt-get install -y \
        zip \
        curl \
        unzip \
        nano

RUN curl -s https://deb.nodesource.com/setup_20.x | bash

RUN apt install nodejs -y

EXPOSE 81

# Run the node app
CMD ["node", "app.js"]