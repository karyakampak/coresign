# # Use the official Python image from the Docker Hub
# FROM python:3.11-slim

# # Set the working directory in the container
# WORKDIR /app

# # RUN mkdir certificate

# # Install Flask
# RUN pip install Flask SQLAlchemy psycopg2-binary

# # Copy the application code into the container
# # COPY app.py .

# # Expose port 5000
# EXPOSE 5000

# # Run the Flask app
# CMD ["python", "app.py"]

# Use the official Ubuntu image as a base
FROM ubuntu:latest

# Set environment variables to prevent some issues with Debian frontend
ENV DEBIAN_FRONTEND=noninteractive

USER root

# RUN mkdir /var/www/html/certificate

RUN apt-get update && apt-get install -y \
        cmake \
        zip \
        curl \
        unzip \
        nano \
        make \
        python3-pip

# RUN curl -s https://deb.nodesource.com/setup_20.x | bash
                
# RUN apt install nodejs -y

COPY library /home/library

WORKDIR /home/library/openssl-3.3.1

RUN make install

RUN apt remove --purge openssl -y

RUN rm -f /lib/x86_64-linux-gnu/libssl.so.*

RUN rm -f /lib/x86_64-linux-gnu/libcrypto.so.*

RUN cp libssl.so.* /lib/x86_64-linux-gnu/

RUN cp libcrypto.so.* /lib/x86_64-linux-gnu/

RUN apt install -y python3-flask python3-sqlalchemy python3-psycopg2

# WORKDIR /home/library/coresign/build

#vRUN cmake ..

# RUN make

WORKDIR /var/www/html

ENV PATH="/usr/local/ssl/bin:${PATH}"

# EXPOSE 5002

# Run the node app
CMD ["python3", "app.py"]
