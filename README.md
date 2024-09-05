# Projeto de Autenticação e CRUD com Regras de Acesso
Este projeto implementa um sistema de autenticação de usuários e CRUD (Create, Read, Update, Delete) com regras de acesso baseadas no usuário autenticado. Ele está dividido em três partes principais: cadastro e login, visualização da lista de usuários e restrição de acesso à edição e exclusão. Esse guia é ideal para quem deseja aprender a construir uma solução de autenticação robusta com permissões personalizadas.

## Estrutura do Projeto
Cadastro e Login: Criação de contas e autenticação de usuários.
Visualização da Lista de Usuários: Permite listar usuários sem expor dados sensíveis.
Restrição de Edição e Exclusão: Limita as operações de edição e exclusão apenas aos dados do próprio usuário logado.
Esta abordagem garante segurança básica e controle adequado sobre o acesso aos dados de usuários em sistemas CRUD.

### Referências
- Documentação do Varela sobre Autenticação
- Tutorial CRUDE: CRUD Simples com Node.js e SQLite

## 1. Cadastro e Login
### Banco de Dados (SQLite)
Crie uma tabela para armazenar os dados dos usuários, incluindo informações como ```id```, ```username```, ```password``` (armazenada com hash) e ```email```. Para proteger as senhas, utilize uma função de hash forte, como bcrypt.

Exemplo de criação da tabela de usuários:
```sql
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  email TEXT NOT NULL
);
```
### Cadastro de Usuário
Implemente uma rota para permitir o cadastro de novos usuários. A senha deve ser armazenada de forma segura, utilizando hash com bcrypt.

Exemplo de lógica para cadastro de usuário (em Python usando Flask e SQLite):

```python
import bcrypt
from flask import request, jsonify
import sqlite3

def cadastrar_usuario():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    # Gera o hash da senha
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO usuarios (username, password, email) VALUES (?, ?, ?)", 
                    (username, hashed_password, email))
        con.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "Nome de usuário ou email já está em uso!"}), 400
    finally:
        con.close()
```
### Login
Implemente uma rota para realizar o login, verificando o nome de usuário e a senha. Após uma autenticação bem-sucedida, armazene uma sessão ou token de autenticação.

Exemplo de lógica para login:

```python
def login():
    username = request.form['username']
    password = request.form['password']

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute("SELECT id, password FROM usuarios WHERE username = ?", (username,))
    user = cur.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        # Login bem-sucedido, armazenar o ID do usuário na sessão
        session['user_id'] = user[0]
        return jsonify({"message": "Login bem-sucedido!"})
    else:
        return jsonify({"message": "Usuário ou senha inválidos!"}), 401
```
## Observações de Segurança
- Hashing de Senhas: Utilize bcrypt para armazenar senhas de forma segura.
- Gerenciamento de Sessão: Utilize cookies seguros ou tokens (JWT) para gerenciar a autenticação, garantindo que o usuário continue autenticado entre requisições.

## 2. Visualização da Lista de Usuários
Apenas usuários autenticados podem visualizar a lista de usuários. Os dados exibidos não devem incluir informações sensíveis, como senhas.

Exemplo de rota para listar usuários:

```python
def listar_usuarios():
    if 'user_id' not in session:
        return jsonify({"message": "Acesso negado! Faça login."}), 403

    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute("SELECT id, username, email FROM usuarios")
    users = cur.fetchall()
    con.close()

    return jsonify(users)
```
## Considerações de Segurança
- Proteção de Dados Sensíveis: Não exponha informações confidenciais como senhas ou tokens.
- Filtragem de Dados: Apenas campos não confidenciais devem ser retornados ao cliente.

## 3. Restrição de Acesso: Edição e Exclusão
Apenas o usuário autenticado pode editar ou excluir seus próprios dados. Isso é garantido verificando se o id do usuário logado corresponde ao id do registro a ser alterado.

Exemplo de Restrição para Edição:

```python
def editar_usuario(id):
    if 'user_id' not in session:
        return jsonify({"message": "Acesso negado! Faça login."}), 403
    
    if session['user_id'] != id:
        return jsonify({"message": "Você não tem permissão para editar este usuário!"}), 403

    return jsonify({"message": "Usuário editado com sucesso!"})
```
Exemplo de Restrição para Exclusão:
```python
def excluir_usuario(id):
    if 'user_id' not in session:
        return jsonify({"message": "Acesso negado! Faça login."}), 403
    
    if session['user_id'] != id:
        return jsonify({"message": "Você não tem permissão para excluir este usuário!"}), 403
    return jsonify({"message": "Usuário excluído com sucesso!"})
```
Considerações de Segurança
Validação do `ID` do Usuário: Sempre compare o ``ID`` do usuário autenticado com o registro que está sendo modificado para evitar acesso indevido.
Feedback Adequado: Forneça mensagens de erro claras e seguras em caso de tentativas de acesso não autorizado.
