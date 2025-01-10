docker compose up --build -d 

pip install -r requirements.txt
PYTHONPATH=. PROXY_SERVER_ADDRESS=localhost PROXY_SERVER_PORT=53 PROXY_CLIENT_ADDRESS=localhost PROXY_CLIENT_PORT=52 python dns_tunnel/socks_client.py
PYTHONPATH=. PROXY_SERVER_ADDRESS=localhost PROXY_SERVER_PORT=53 PROXY_CLIENT_ADDRESS=localhost PROXY_CLIENT_PORT=52 python dns_tunnel/socks_server.py