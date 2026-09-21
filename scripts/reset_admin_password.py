# scripts/reset_admin_password.py
# One-time safe admin password reset
# Nunca executa automaticamente: startup, migrate.py, Gunicorn, deploy
# Invocar exatamente uma vez apenas com a variável de ambiente ADMIN_PASSWORD_RESET

import os
import sys

from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User
from config import Config


def main():
    # 1. Start the Flask application context correctly
    from servidor import app

    with app.app_context():
        # 2. Find exactly: username = "admin"
        admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()

        # 3. If admin does not exist: fail safely, do not create a new account
        if not admin:
            print("Falha: usuario admin nao encontrado no banco de dados.")
            print("Nao e permitido criar nova conta automaticamente.")
            sys.exit(1)

        # 4. Read the new password from an environment variable: ADMIN_PASSWORD_RESET
        new_password = os.getenv("ADMIN_PASSWORD_RESET", "")

        # 5. Reject execution if the variable is missing or empty
        if not new_password:
            print("Falha: variavel de ambiente ADMIN_PASSWORD_RESET nao definida ou vazia.")
            print("Defina ADMIN_PASSWORD_RESET com a nova senha antes de executar novamente.")
            sys.exit(1)

        # 6. Generate the new hash using the SAME hashing function already used by the application
        new_hash = generate_password_hash(new_password)
        admin.password_hash = new_hash

        # 7. Commit the transaction once
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Falha ao commitar alteracoes no banco: {e}")
            sys.exit(1)

        # 8. Verify internally with check_password_hash() that the new password matches
        if not admin.check_password(new_password):
            print("Falha: verificacao interna com check_password_hash falhou.")
            sys.exit(1)

        # 9. Print only a safe success/failure message (no passwords, no hashes)
        print("Sucesso: senha do administrador 'admin' foi atualizada com sucesso.")
        print("A nova senha ja pode ser utilizada para fazer login.")
        sys.exit(0)


if __name__ == "__main__":
    main()