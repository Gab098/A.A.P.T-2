# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Install system dependencies for Prowler and git
RUN apt-get update && apt-get install -y \
    git \
    jq \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the common framework modules
COPY aapt_framework/common /app/aapt_framework/common

# Copy the current worker directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install Prowler
# Prowler can be installed via pip or by cloning the repo. Pip is generally easier for Docker.
RUN pip install prowler --no-cache-dir

# Make port 80 available to the world outside this container
EXPOSE 8080

# Define environment variable
ENV WORKER_NAME cloud_recon_worker

# Run main.py when the container launches
CMD ["python", "main.py"]
