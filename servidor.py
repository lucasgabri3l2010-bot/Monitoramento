from flask import Flask, request, jsonify, render_template
from datetime import datetime

app = Flask(__name__)

computadores = {}


@app.route("/")
def painel():
    return render_template("index.html")


@app.route("/dados")
def dados():
    agora = datetime.now()

    resultado = {}

    for nome, computador in computadores.items():

        ultimo_contato = datetime.strptime(
            computador["ultimo_contato"],
            "%d/%m/%Y %H:%M:%S"
        )

        segundos = (agora - ultimo_contato).total_seconds()

        if segundos <= 15:
            status = "online"
        else:
            status = "offline"

        resultado[nome] = {
            **computador,
            "status": status
        }

    return jsonify(resultado)


@app.route("/monitoramento", methods=["POST"])
def receber_dados():

    dados = request.json

    nome = dados["computador"]

    computadores[nome] = {
        "ip": dados["ip"],
        "cpu": dados["cpu"],
        "ram": dados["ram"],
        "disco": dados["disco"],
        "ultimo_contato": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }

    print(f"Dados recebidos de {nome}")

    return jsonify({"status": "ok"})


app.run(host="0.0.0.0", port=5000)