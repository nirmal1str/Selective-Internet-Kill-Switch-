import os
import socket
import threading
import time
import webbrowser

from werkzeug.serving import make_server

from app import app


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGIS_PORT", find_free_port()))
    server = make_server(host, port, app)
    url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print("AEGIS is running.")
    print(f"Opening {url}")
    print("PIN: 2468 unless AEGIS_PIN is set.")
    print("Close this window to stop the dashboard process.")
    time.sleep(0.6)
    webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
