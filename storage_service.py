"""
Givova Transportes - Serviço de Armazenamento de Objetos (Cloudflare R2)
Finalidade: Gerenciar o ciclo de vida dos binários de releases do GivovaMonitorAgent no Cloudflare R2
            usando a API S3-compatible com presigned URLs, streaming e verificação estrita de integridade.
Garantias:
1. Nenhuma credencial/segredo exposta em logs, APIs ou exceções.
2. URLs assinadas com validade curta e restritas exclusivamente a GET do objeto alvo.
3. Validação rigorosa de chaves de objeto contra directory traversal e caracteres ilegais.
4. Verificação de integridade ponta-a-ponta via SHA-256 streaming.
"""

import os
import re
import hashlib
import logging
from typing import Generator, Optional, Tuple, Dict, Any

import boto3
from botocore.client import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError

from config import Config

logger = logging.getLogger("GivovaStorage")

# Padrão seguro para chaves de objeto de releases:
# ex: agents/1.5.0/GivovaMonitorAgent.exe ou agents/1.6.0-rc1/GivovaMonitorAgent.exe
OBJECT_KEY_REGEX = re.compile(r"^agents/[0-9a-zA-Z._-]+/[0-9a-zA-Z._-]+\.exe$")


def mask_secret(value: str) -> str:
    """Retorna versão mascarada de segredo para logs seguros."""
    if not value:
        return "<nao-definido>"
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}...{value[-4:]}"


def validate_object_key(object_key: str) -> str:
    """
    Valida a chave do objeto no R2 contra directory traversal e injeções.
    Levanta ValueError se a chave violar a estrutura canônica esperada.
    """
    if not object_key or not isinstance(object_key, str):
        raise ValueError("Chave de objeto R2 inválida ou vazia.")

    cleaned = object_key.strip()
    if ".." in cleaned or "\\" in cleaned or cleaned.startswith("/"):
        raise ValueError(f"Chave de objeto contém caracteres ou caminhos inválidos: '{cleaned}'")

    if not OBJECT_KEY_REGEX.match(cleaned):
        raise ValueError(
            f"Chave de objeto '{cleaned}' não corresponde ao padrão oficial 'agents/<versao>/<arquivo>.exe'"
        )

    return cleaned


def is_r2_configured() -> bool:
    """Verifica se todas as variáveis mandatórias do Cloudflare R2 foram informadas."""
    return bool(
        Config.R2_ENDPOINT_URL
        and Config.R2_ACCESS_KEY_ID
        and Config.R2_SECRET_ACCESS_KEY
        and Config.R2_BUCKET_NAME
    )


def get_r2_client():
    """
    Cria e retorna cliente boto3 configurado para a API S3-compatible do Cloudflare R2.
    Levanta RuntimeError se as credenciais obrigatórias não estiverem configuradas.
    """
    if not is_r2_configured():
        missing = []
        if not Config.R2_ENDPOINT_URL:
            missing.append("R2_ENDPOINT_URL")
        if not Config.R2_ACCESS_KEY_ID:
            missing.append("R2_ACCESS_KEY_ID")
        if not Config.R2_SECRET_ACCESS_KEY:
            missing.append("R2_SECRET_ACCESS_KEY")
        if not Config.R2_BUCKET_NAME:
            missing.append("R2_BUCKET_NAME")
        raise RuntimeError(f"Cloudflare R2 não configurado. Variáveis ausentes: {', '.join(missing)}")

    boto_config = BotoConfig(
        signature_version="s3v4",
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=10,
        read_timeout=30
    )

    return boto3.client(
        "s3",
        endpoint_url=Config.R2_ENDPOINT_URL,
        aws_access_key_id=Config.R2_ACCESS_KEY_ID,
        aws_secret_access_key=Config.R2_SECRET_ACCESS_KEY,
        region_name=Config.R2_REGION or "auto",
        config=boto_config
    )


def object_exists(object_key: str, client=None) -> bool:
    """Verifica se o objeto existe no bucket R2 via head_object."""
    clean_key = validate_object_key(object_key)
    s3 = client or get_r2_client()
    try:
        s3.head_object(Bucket=Config.R2_BUCKET_NAME, Key=clean_key)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("404", "NoSuchKey"):
            return False
        logger.warning(f"Erro ao verificar existência de '{clean_key}' no R2: {code}")
        raise
    except Exception as e:
        logger.warning(f"Falha de rede ao consultar '{clean_key}' no R2: {e}")
        raise


def get_object_metadata(object_key: str, client=None) -> Optional[Dict[str, Any]]:
    """Obtém metadados do objeto (tamanho, etag, custom metadata) sem baixar o corpo."""
    clean_key = validate_object_key(object_key)
    s3 = client or get_r2_client()
    try:
        resp = s3.head_object(Bucket=Config.R2_BUCKET_NAME, Key=clean_key)
        return {
            "size": resp.get("ContentLength", 0),
            "content_type": resp.get("ContentType"),
            "etag": (resp.get("ETag") or "").strip('"'),
            "last_modified": resp.get("LastModified"),
            "metadata": resp.get("Metadata", {})
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("404", "NoSuchKey"):
            return None
        logger.warning(f"Erro ao obter metadados de '{clean_key}' no R2: {code}")
        raise


def upload_file(
    local_path: str,
    object_key: str,
    content_type: str = "application/vnd.microsoft.portable-executable",
    metadata: Optional[Dict[str, str]] = None,
    client=None
) -> Dict[str, Any]:
    """
    Realiza o upload seguro de arquivo local para o Cloudflare R2.
    Valida hash SHA-256 local antes do envio e confirma tamanho após upload.
    """
    clean_key = validate_object_key(object_key)
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"Arquivo local não encontrado: {local_path}")

    # 1. Calcula hash SHA-256 e tamanho do arquivo local
    hasher = hashlib.sha256()
    file_size = 0
    with open(local_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            file_size += len(chunk)
    local_sha256 = hasher.hexdigest().lower()

    s3 = client or get_r2_client()
    upload_meta = {
        "sha256": local_sha256,
        "original_size": str(file_size)
    }
    if metadata:
        upload_meta.update(metadata)

    logger.info(
        f"Iniciando upload para R2: '{clean_key}' ({file_size} bytes, SHA: {local_sha256[:16]}...)"
    )

    extra_args = {
        "ContentType": content_type,
        "Metadata": upload_meta
    }

    s3.upload_file(
        Filename=local_path,
        Bucket=Config.R2_BUCKET_NAME,
        Key=clean_key,
        ExtraArgs=extra_args
    )

    # 2. Confirmação pós-upload via head_object
    meta = get_object_metadata(clean_key, client=s3)
    if not meta:
        raise RuntimeError(f"Objeto '{clean_key}' não encontrado no R2 após upload.")

    if meta["size"] != file_size:
        raise ValueError(
            f"Tamanho divergente no R2 após upload: esperado {file_size} bytes, gravado {meta['size']} bytes."
        )

    logger.info(f"Upload para R2 concluído e validado com sucesso: '{clean_key}' ({file_size} bytes).")

    return {
        "object_key": clean_key,
        "size": file_size,
        "sha256": local_sha256,
        "etag": meta["etag"],
        "metadata": meta["metadata"]
    }


def download_stream(object_key: str, chunk_size: int = 65536, client=None) -> Generator[bytes, None, None]:
    """
    Gera chunks de bytes a partir do objeto no Cloudflare R2.
    Utilizado para streaming controlado pelo Render caso o redirect seja desabilitado.
    """
    clean_key = validate_object_key(object_key)
    s3 = client or get_r2_client()
    try:
        resp = s3.get_object(Bucket=Config.R2_BUCKET_NAME, Key=clean_key)
        body = resp.get("Body")
        if not body:
            return
        while chunk := body.read(chunk_size):
            yield chunk
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        logger.warning(f"Erro ao baixar stream de '{clean_key}' do R2: {code}")
        raise


def verify_object(
    object_key: str,
    expected_size: Optional[int] = None,
    expected_sha256: Optional[str] = None,
    client=None
) -> Tuple[bool, str]:
    """
    Valida estritamente a presença, tamanho e hash SHA-256 do objeto gravado no R2.
    Faz download por streaming para cálculo exato do SHA-256.
    """
    clean_key = validate_object_key(object_key)
    s3 = client or get_r2_client()

    meta = get_object_metadata(clean_key, client=s3)
    if not meta:
        return False, f"Objeto '{clean_key}' não existe no bucket R2 '{Config.R2_BUCKET_NAME}'."

    if expected_size is not None and meta["size"] != expected_size:
        return False, f"Tamanho diverge no R2: esperado {expected_size}, encontrado {meta['size']}."

    if expected_sha256:
        exp_clean = expected_sha256.strip().lower()
        hasher = hashlib.sha256()
        for chunk in download_stream(clean_key, client=s3):
            hasher.update(chunk)
        actual_sha = hasher.hexdigest().lower()

        if actual_sha != exp_clean:
            return False, f"SHA-256 diverge no R2: esperado {exp_clean}, obtido {actual_sha}."

    return True, "Objeto validado com 100% de integridade."


def generate_presigned_download_url(
    object_key: str,
    expires_in: int = 180,
    filename: Optional[str] = None,
    client=None
) -> str:
    """
    Gera Presigned URL temporária para download direto do Cloudflare R2.
    - Validade padrão: 180 segundos (3 minutos).
    - Permite exclusivamente operação 'get_object' sobre o objeto específico.
    - O bucket permanece rigorosamente privado.
    - Nenhuma credencial é exposta no log.
    """
    clean_key = validate_object_key(object_key)
    s3 = client or get_r2_client()

    params: Dict[str, Any] = {
        "Bucket": Config.R2_BUCKET_NAME,
        "Key": clean_key
    }
    if filename:
        clean_fn = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        params["ResponseContentDisposition"] = f'attachment; filename="{clean_fn}"'
        params["ResponseContentType"] = "application/vnd.microsoft.portable-executable"

    url = s3.generate_presigned_url(
        ClientMethod="get_object",
        Params=params,
        ExpiresIn=max(60, min(expires_in, 3600))
    )

    logger.info(
        f"Presigned URL gerada para '{clean_key}' (validade: {expires_in}s, filename: '{filename or clean_key}')"
    )

    return url
