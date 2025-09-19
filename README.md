# Proxy Server (Python)
A multi-threaded HTTP/HTTPS forward proxy implemented in Python.
## Features
- HTTP request forwarding
- HTTPS tunneling (CONNECT)
- Basic Authentication (Proxy-Authorization: Basic ...)
- Domain filtering (`blocked.txt`)
- Simple file-based caching for GET responses (`cache/`)
- Request logging (`proxy.log`)
## Setup & Run
1. Put the project files in a folder:




Demo steps
Start the proxy.
Point your browser to use the proxy.
Access http://example.com — should load and create a cache file.
Refresh — you should see [CACHE HIT] in proxy.log .
Try http://facebook.com — proxy returns a blocked page.
Access https://www.google.com — works via CONNECT tunneling.
Important notes
This project is for educational/demo use only. Do not use as-is in production.
Authentication credentials in users.txt are stored in plaintext for demo purposes.
Cache does not implement TTL or validation. You can extend this by parsing Cache-Control ,
ETag , etc.
