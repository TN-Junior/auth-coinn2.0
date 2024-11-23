import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import datetime
from urllib.parse import quote_plus

# Carregar variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

# Verificação das variáveis de ambiente essenciais
secret_key = os.getenv('SECRET_KEY')
database_uri = os.getenv('SQLALCHEMY_DATABASE_URI')

if not secret_key or not database_uri:
    raise ValueError("As variáveis de ambiente 'SECRET_KEY' ou 'SQLALCHEMY_DATABASE_URI' não estão definidas.")

# Codificar senha na URI do banco de dados, se necessário
if 'mysql://' in database_uri:
    database_uri = database_uri.replace('mysql://', 'mysql+pymysql://')
    # Exemplo para codificar a senha manualmente caso contenha caracteres especiais
    if "@" in database_uri.split(":")[2]:
        user, password_host = database_uri.split("//")[1].split(":", 1)
        password, host = password_host.split("@", 1)
        encoded_password = quote_plus(password)
        database_uri = f"mysql+pymysql://{user}:{encoded_password}@{host}"

# Configuração do Flask utilizando variáveis de ambiente
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# Classe de usuários
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Rota de registro de usuários
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')

        # Verificação de campos obrigatórios
        if not name or not email or not password:
            return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

        # Verificar se o email já está registrado
        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'Usuário já registrado com este email'}), 400

        # Hash da senha e criação do usuário
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = Users(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'Usuário registrado com sucesso'}), 201

    except Exception as e:
        app.logger.error(f'Erro ao registrar usuário: {e}')
        db.session.rollback()
        return jsonify({'message': f'Ocorreu um erro ao registrar o usuário: {str(e)}'}), 500

# Rota de login de usuários
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

        user = Users.query.filter_by(email=email).first()

        if not user:
            return jsonify({'message': 'Credenciais inválidas: usuário não encontrado'}), 401

        if not check_password_hash(user.password, password):
            return jsonify({'message': 'Credenciais inválidas: senha incorreta'}), 401

        # Geração do token JWT
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({'token': token, 'redirect_url': '/dashboard'}), 200

    except Exception as e:
        app.logger.error(f'Erro ao fazer login: {e}')
        return jsonify({'message': f'Ocorreu um erro ao fazer login: {str(e)}'}), 500

# Rota de redefinição de senha
@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('newPassword')

        if not email or not new_password:
            return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

        # Verificar se o usuário com o email existe
        user = Users.query.filter_by(email=email).first()

        if not user:
            return jsonify({'message': 'Usuário não encontrado'}), 404

        # Atualizar a senha do usuário
        user.password = generate_password_hash(new_password, method='sha256')
        db.session.commit()

        return jsonify({'message': 'Senha redefinida com sucesso!'}), 200

    except Exception as e:
        app.logger.error(f'Erro ao redefinir senha: {e}')
        db.session.rollback()
        return jsonify({'message': f'Ocorreu um erro ao redefinir a senha: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)





