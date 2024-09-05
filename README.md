# Projeto de Autenticação e CRUD com Regras de Acesso

Este projeto implementa um sistema de autenticação de usuários e CRUD (Create, Read, Update, Delete) com regras de acesso. Ele está dividido em três partes principais: cadastro e login, visualização de usuários e restrição de acesso à edição e exclusão.

## Divisão:
- 1: Implementação do cadastro e login.
- 2: Visualização da lista de usuários sem expor dados sensíveis.
- 3: Restrição de edição e exclusão baseada no ID do usuário logado.
Essa estrutura orientará seus alunos na implementação de uma solução robusta para autenticação e autorização em sistemas CRUD.

### Documentação
Para mais detalhes, consulte a documentação do Varela: (https://github.com/prof-varela/2024-tri2-ia22-autenticacao).

E este é um link para o tutorial do CRUDE:(https://github.com/prof-varela/tutoriais/blob/main/tutorial/crud-simples-monoservidor-nodejs-typescript-express-sqlite.md).

## 1. Cadastro e Login

### Banco de Dados (SQLite)

Criar uma tabela para armazenar os dados dos usuários, como `id`, `username`, `password` (idealmente criptografada com hash) e `email`.

#### Exemplo de criação da tabela de usuários:

```sql
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  email TEXT
);
```
### adastro de Usuário:
Crie uma rota para que novos usuários possam se cadastrar. A senha deve ser criptografada antes de ser armazenada no banco de dados.

Exemplo de lógica no backend (em Python usando Flask e SQLite):

```python
import bcrypt
from flask import request, jsonify
import sqlite3

def cadastrar_usuario():
    username = request.form['username']
    password = request.form['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, hashed_password))
    con.commit()
    con.close()

    return jsonify({"message": "Usuário cadastrado com sucesso!"})
```
### Login: 
Implemente uma rota de login que verifica o nome de usuário e a senha. Se o login for bem-sucedido, gere uma sessão ou token para o usuário logado.

Exemplo de verificação de login:

```python
def login():
    username = request.form['username']
    password = request.form['password']

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute("SELECT id, password FROM usuarios WHERE username = ?", (username,))
    user = cur.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        # Login bem-sucedido, armazenar sessão ou token
        session['user_id'] = user[0]
        return jsonify({"message": "Login bem-sucedido!"})
    else:
        return jsonify({"message": "Usuário ou senha inválidos!"}), 401
```
## 2. Ver Lista de Usuários:
Após o login, o usuário pode visualizar a lista de pessoas cadastradas, porém sem exibir informações sensíveis (como senhas).

Exemplo de rota para listar usuários:

```python
def listar_usuarios():
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute("SELECT id, username, email FROM usuarios")
    users = cur.fetchall()
    con.close()

    return jsonify(users)
```
## 3. Restrição de Acesso (Edição e Exclusão):
O usuário logado só pode alterar ou excluir os próprios dados. Isso pode ser feito verificando se o `id` do usuário logado corresponde ao `id` do registro a ser alterado.

Exemplo de restrição de edição:

````python
def editar_usuario(id):
    if session['user_id'] != id:
        return jsonify({"message": "Você não tem permissão para editar este usuário!"}), 403
````
