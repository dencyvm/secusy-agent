# Use an official Python runtime as a parent image
FROM python:3.10

# Set environment variables
ENV PYTHONUNBUFFERED=1
RUN apt-get update
RUN apt-get install libpcap-dev -y

# Set the working directory in the container
WORKDIR /code

# Install dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /code
COPY . /code/

# Expose the port the app runs on
EXPOSE 8099

# Start the WebSocket consumer
CMD ["daphne", "-u", "websockets:8099", "scannerWebSocket.routing.application"]