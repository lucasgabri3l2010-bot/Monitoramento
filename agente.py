import socket
import psutil
import time
import os
import requests

SERVIDOR = "http://192.168.100.14:5000/monitoramento"

while True:

    nome_pc = socket.gethostname()
    ip = socket.gethostbyname(nome_pc)

    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disco = psutil.disk_usage("C:\\").percent

    dados = {
        "computador": nome_pc,
        "ip": ip,
        "cpu": cpu,
        "ram": ram,
        "disco": disco
    }

    try:
        resposta = requests.post(SERVIDOR, json=dados)

        if resposta.status_code == 200:
            status = "Dados enviados com sucesso"
        else:
            status = f"Erro HTTP: {resposta.status_code}"

    except requests.exceptions.RequestException:
        status = "Servidor indisponível"

    os.system("cls")

    print("===== AGENTE DE MONITORAMENTO =====")
    print()
    print(f"Computador: {nome_pc}")
    print(f"IP: {ip}")
    print()
    print(f"CPU: {cpu}%")
    print(f"RAM: {ram}%")
    print(f"Disco: {disco}%")
    print()
    print(status)
    print()
    print("Atualizando a cada 5 segundos...")

    time.sleep(5)
    