#!/usr/bin/env python3
"""
Givova Transportes - Script de Upload de Release para Cloudflare R2
Finalidade: Realizar o upload seguro e com validação criptográfica do executável
            GivovaMonitorAgent.exe para o bucket Cloudflare R2, atualizando os metadados
            da release no PostgreSQL sem apagar o binary_data legado.

Uso:
    python scripts/upload_release_to_r2.py --version 1.5.0 --file dist/GivovaMonitorDeploy/GivovaMonitorAgent.exe
"""

import os
import sys
import argparse
import hashlib
import logging

# Garante que o diretório raiz do projeto esteja no sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(BASE_DIR, ".env"))

from config import Config
from models import db, AgentRelease
from servidor import app
import storage_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("R2Upload")


def compute_file_sha256_and_size(file_path: str) -> tuple[str, int]:
    """Calcula hash SHA-256 e tamanho exato de um arquivo em disco."""
    hasher = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest().lower(), size


def find_default_exe(version: str) -> str | None:
    """Busca executável local padrão para a versão informada."""
    clean_v = version.strip().lstrip("vV")
    candidates = [
        os.path.join(BASE_DIR, "releases", clean_v, "GivovaMonitorAgent.exe"),
        os.path.join(BASE_DIR, "dist", "GivovaMonitorDeploy", "GivovaMonitorAgent.exe"),
        os.path.join(BASE_DIR, "dist", "GivovaMonitorAgent.exe"),
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return None


def main():
    parser = argparse.ArgumentParser(description="Upload de release do Givova Monitor para Cloudflare R2")
    parser.add_argument("--version", "-v", required=True, help="Versão da release (ex: 1.5.0)")
    parser.add_argument("--file", "-f", default=None, help="Caminho do GivovaMonitorAgent.exe local")
    parser.add_argument("--force", action="store_true", help="Sobrescreve objeto no R2 caso já exista")
    parser.add_argument("--dry-run", action="store_true", help="Executa verificações sem realizar upload")

    args = parser.parse_args()
    version = args.version.strip().lstrip("vV")

    # 1. Localiza o executável local
    file_path = args.file
    if not file_path:
        file_path = find_default_exe(version)

    if not file_path or not os.path.exists(file_path):
        logger.error(f"Executável para a versão {version} não encontrado. Especifique --file <caminho>.")
        sys.exit(1)

    # 2. Calcula SHA-256 e tamanho do executável local
    local_sha256, local_size = compute_file_sha256_and_size(file_path)
    logger.info(f"Arquivo local: {file_path}")
    logger.info(f"Tamanho: {local_size} bytes ({local_size / (1024*1024):.2f} MB)")
    logger.info(f"SHA-256 Local: {local_sha256}")

    # 3. Valida release no banco de dados
    with app.app_context():
        rel = AgentRelease.query.filter_by(version=version).first()
        if not rel:
            logger.error(f"Release v{version} não encontrada no banco de dados!")
            sys.exit(1)

        db_sha256 = (rel.sha256 or "").strip().lower()
        logger.info(f"SHA-256 Registrado no Banco: {db_sha256}")

        if local_sha256 != db_sha256:
            logger.critical(
                f"ABORTADO: O hash do arquivo local ({local_sha256}) difere do hash registrado no banco ({db_sha256})!"
            )
            sys.exit(1)

        logger.info("Integridade SHA-256 local confirmada com a release do banco de dados.")

        # 4. Verifica configuração do Cloudflare R2
        if not storage_service.is_r2_configured():
            logger.error(
                "Credenciais do Cloudflare R2 não configuradas no ambiente.\n"
                "Defina as variáveis no .env ou no ambiente:\n"
                "  - R2_ENDPOINT_URL\n"
                "  - R2_ACCESS_KEY_ID\n"
                "  - R2_SECRET_ACCESS_KEY\n"
                "  - R2_BUCKET_NAME (padrão: givova-monitor-releases)\n"
                "  - R2_REGION (padrão: auto)"
            )
            sys.exit(1)

        object_key = f"agents/{version}/GivovaMonitorAgent.exe"
        logger.info(f"Chave canônica no R2: {object_key}")

        if args.dry_run:
            logger.info("[DRY-RUN] Todas as validações preliminares passaram com sucesso. Upload não executado.")
            sys.exit(0)

        # 5. Verifica se o objeto já existe no R2
        client = storage_service.get_r2_client()
        already_exists = storage_service.object_exists(object_key, client=client)

        if already_exists and not args.force:
            logger.info(f"Objeto '{object_key}' já existe no bucket R2. Validando integridade...")
            valid, reason = storage_service.verify_object(
                object_key,
                expected_size=local_size,
                expected_sha256=local_sha256,
                client=client
            )
            if valid:
                logger.info(f"Objeto no R2 já está íntegro e idêntico ao binário oficial.")
            else:
                logger.error(f"Objeto no R2 existente difere do binário oficial ({reason}). Use --force para sobrescrever.")
                sys.exit(1)
        else:
            # 6. Executa upload seguro
            logger.info(f"Enviando '{file_path}' para 'r2://{Config.R2_BUCKET_NAME}/{object_key}'...")
            upload_res = storage_service.upload_file(
                local_path=file_path,
                object_key=object_key,
                metadata={
                    "version": version,
                    "sha256": local_sha256,
                    "channel": rel.release_channel or "stable",
                    "scope": rel.rollout_scope or "global"
                },
                client=client
            )
            logger.info(f"Upload concluído. ETag: {upload_res['etag']}")

            # 7. Validação estrita pós-upload
            logger.info("Realizando verificação de download e conferência de hash SHA-256 no R2...")
            valid, reason = storage_service.verify_object(
                object_key,
                expected_size=local_size,
                expected_sha256=local_sha256,
                client=client
            )
            if not valid:
                logger.critical(f"FALHA CRÍTICA DE INTEGRIDADE PÓS-UPLOAD: {reason}")
                sys.exit(1)
            logger.info("Verificação de integridade R2 aprovada com 100% de sucesso!")

        # 8. Atualiza metadados da release no PostgreSQL
        logger.info("Atualizando metadados da release no banco de dados...")
        rel.storage_type = "r2"
        rel.object_key = object_key
        rel.file_size = local_size
        # Preserva binary_data como fallback temporário de segurança
        db.session.commit()

        logger.info(f"Release v{version} atualizada com sucesso para Cloudflare R2!")
        logger.info(f"  - storage_type: {rel.storage_type}")
        logger.info(f"  - object_key: {rel.object_key}")
        logger.info(f"  - file_size: {rel.file_size} bytes")
        logger.info(f"  - binary_data preservado para fallback temporário.")
        print("\n========================================================")
        print(f" MIGRACAO PARA CLOUDFLARE R2 CONCLUIDA COM SUCESSO!")
        print(f" Versao: {version}")
        print(f" Bucket: {Config.R2_BUCKET_NAME}")
        print(f" Objeto: {object_key}")
        print(f" SHA-256: {local_sha256}")
        print("========================================================\n")


if __name__ == "__main__":
    main()
