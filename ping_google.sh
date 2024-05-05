#!/bin/bash

# URL to access
url="http://www.google.com"

# Infinite loop to continuously send HTTP requests
while true; do
    # Send an HTTP GET request to the URL
    curl -s $url > /dev/null
    echo "Sent request at $(date)"  # Log the time of the request

    # Wait for 0.2 seconds before the next request
    sleep 0.2
done

