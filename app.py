from flask import Flask
from flask import jsonify
from flask import render_template
from flask import redirect
from flask import url_for
from flask import request
from flask import flash
from flask import session
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import PasswordField
from wtforms import SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
import logging 

'''
@ Configuração do Flask
'''
app = Flask(__name__)
app.config['SECRET_KEY'] = '123'
bcrypt = Bcrypt(app)

'''
@ Configuração de logging
'''
logging.basicConfig(level=logging.DEBUG)

# MongoDB setup
client = MongoClient('localhost', 27017)
db = client['login_db']
users_collection = db['users']

'''
@ Formulário de login
'''
class LoginForm(FlaskForm):
    usuario = StringField('Usuário', validators=[DataRequired(), Length(min=4, max=25)])
    senha = PasswordField('Senha', validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField('Login')

'''
@ Rota para página inicial
'''
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usuario = form.usuario.data
        senha = form.senha.data
        try:           
            # Check if user exists
            usuario_db = users_collection.find_one({'usuario': usuario})
            if usuario_db and bcrypt.check_password_hash(usuario_db['senha'], senha):
                session['usuario'] = usuario
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('home'))
        except Exception as e:
            app.logger.error(e)
            flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html', form=form)

'''
@ Rota para página home
'''
@app.route('/home')
def home():
    if 'usuario' in session:
        return render_template('index.html', usuario=session['usuario'])
    else:
        return redirect(url_for('login'))

'''
@ Rota para logout
'''
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

'''
@ API - Rota para adicionar usuário
'''
@app.route('/api/user', methods=['POST'])
def adicionar_usuario():
    dados = request.json
    
    # Validate username length
    if 'usuario' not in dados or len(dados['usuario']) < 8:
        return {'message': 'Username must be at least 8 characters long'}, 400
    
    # Hash the password
    if 'senha' in dados:
        dados['senha'] = bcrypt.generate_password_hash(dados['senha'],10).decode('utf-8')
    else:
        return {'message': 'Password is required'}, 400
    
    resultado = users_collection.insert_one(dados)
    
    return {
        'message': 'Usuário adicionado com sucesso!',
        'id': str(resultado.inserted_id)
    }, 201

'''
@ API - Rota para listar usuários
'''
@app.route('/api/user', methods=['GET'])
def listar_usuarios():
    usuarios = list(users_collection.find({}, {'_id': 0}))

    return jsonify(usuarios)

if __name__ == '__main__':
    app.run(port=5000, debug=True)