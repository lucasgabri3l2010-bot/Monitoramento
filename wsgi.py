import os
from servidor import app
from config import Config

if __name__ == "__main__":
    from waitress import serve
    print(f"Iniciando Givova Monitor com Waitress WSGI em http://{Config.HOST}:{Config.PORT}")
    serve(app, host=Config.HOST, port=Config.PORT)
