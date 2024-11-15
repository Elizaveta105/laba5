from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ln555'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://liza_u_nastya:password@localhost/laba_5_rpp'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
# Маршрут для неавторизованных пользователей
login_manager.login_view = 'login'


# Модель пользователя и создание таблицы в базе данных
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(80), nullable=False)


# Получаем пользователя из базы данных по id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Роут для главной страницы лабораторной работы

# Если пользователь авторизован, мы показываем ему главную страницу
# Иначе перенаправляем на страницу входа
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user)
    return redirect(url_for('login'))


# Роут для страницы входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Если пользователь отправил данные
        email = request.form.get('email')
        password = request.form.get('password')  # Получаем из формы email  и пароль
        user = User.query.filter_by(email=email).first()  # Ищем пользователя в базе по email
        if not user:
            flash('Пользователь с таким email не найден!')
        elif not check_password_hash(user.password, password):
            flash('Указан неверный пароль!')
        else:
            login_user(user)
            return redirect(url_for('index'))  # Перенаправляем на главную страницу
    return render_template('login.html')  # Показываем страницу входа


# Роут для страницы регистрации
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Пользователь с таким email уже существует!')
        else:
            new_user = User(
                email=email,
                name=name,
                password=generate_password_hash(password, method='pbkdf2:sha256')
            )
            db.session.add(new_user)  # Добавляем нового пользователя в базу данных
            db.session.commit()  # Сохраняем изменения
            return redirect(url_for('login'))
    return render_template('signup.html')


# Роут для выхода из аккаунта
@app.route('/logout')
@login_required  # Декоратор, который требует авторизации
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():  # Создаем контекст приложения для работы с базой данных
        db.create_all()
    app.run(debug=True)
