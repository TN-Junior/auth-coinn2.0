# Auth Coin


Auth Coin é uma aplicação de autenticação de usuários desenvolvida com **Python**, utilizando o framework **Flask**, com autenticação baseada em **JWT (JSON Web Token)** e persistência de dados em **MySQL**. Este projeto tem como objetivo fornecer uma solução robusta e segura para gerenciar o acesso de usuários em sistemas web.

---

## Funcionalidades

- **Cadastro de Usuários**: Permite registrar novos usuários no sistema.
- **Login**: Gera um token JWT para autenticação de usuários cadastrados.
- **Autenticação JWT**: Protege rotas utilizando tokens JWT.
- **Persistência de Dados**: Registra informações dos usuários em um banco de dados MySQL.

---

## Tecnologias Utilizadas

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)

---

## Requisitos

- **Python 3.9+**
- **MySQL 8.0+**
- Bibliotecas do Python:
  - Flask
  - Flask-JWT-Extended
  - Flask-SQLAlchemy
  - PyMySQL

---

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/auth-coin.git
   cd auth-coin


   python -m venv venv
   
   pip install -r requirements.txt

   SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://usuario:senha@localhost/nome_do_banco'

 #  Rotas Principais
  
  1. Cadastro de Usuário
  Exemplo de Requisição:
  ```bash
  curl -X POST http://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{
  "username": "usuario",
  "password": "senha"
}'

````
Exemplo de Resposta:
```` bash
{
  "message": "Usuário registrado com sucesso"
}
````
2. Login
Exemplo de Requisição:
  ```bash
curl -X POST http://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{
  "username": "usuario",
  "password": "senha"
}'




  
  

  
