from flask import Flask, session, redirect, url_for, render_template, request, g, flash
from flask.ext.bcrypt import Bcrypt
import sqlite3

import sys

app = Flask(__name__)
app.config.update(
    DATABASE=sys.argv[1],
    SECRET_KEY='aufgaofyawgfcjhavywefvakbfvaywe283rtfwegydbha',
    HOST='0.0.0.0',
    PORT=5000
)

bcrypt = Bcrypt(app)


@app.route('/', methods=['GET', 'POST'])
def index():
    # first time setup
    if request.method == 'POST':
        if request.form['type'] == 'setup' and query_db('select count(*) from users', one=True)[0] == 0:
            new_user(request.form['name'], request.form['password'], admin=True)
            return redirect(url_for('index'))
    if query_db('select count(*) from users', one=True)[0] == 0:
        return '''
            <form action="" method="post">
                <input type=hidden name=type value="setup">
                <p>Create the first admin user</p>
                <p>Name: <input type=text name=name></p>
                <p>Password: <input type=password name=password></p>
                <input type=submit value=Create>
            </form>
            '''

    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'login' in request.form and request.form['type'] == 'login':
        name = request.form['name']
        password = request.form['password']
        # validate the user
        user = query_db('select user_id, name, password, admin from users where name = ?', [name], one=True)
        if check_password(user[0], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['admin'] = bool(user[3])
            session['logged_in'] = True
            flash('Logged in')
            return redirect(url_for('index'))
        else:
            flash('Name or password wrong.')
    return render_template('login.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST' and session.get('logged_in', False) and request.form['type'] == 'shout':
        update_db('insert into shouts(user_id, shout, post_time) values (?, ?, datetime(\'now\', \'localtime\'))', [session['user_id'], request.form['content']])
        return redirect(url_for('chat'))

    if session.get('logged_in', False):
        shouts = []
        for shout in query_db('select name, shout, strftime(\'%Y-%m-%d %H:%M\', post_time) from users natural join shouts order by shout_id desc limit 15'):
            shouts.insert(0, (shout[0], shout[1], shout[2]))
        return render_template('chat.html', shouts=shouts)

    return redirect(url_for('index'))

@app.route('/chat_log')
@app.route('/chat_log/<int:amount>')
def chat_log(amount=50):
    if session.get('logged_in', False):
        shouts = []
        for shout in query_db('select name, shout, strftime(\'%Y-%m-%d %H:%M\', post_time) from users natural join shouts limit ?', [amount]):
            shouts.insert(0, (shout[0], shout[1], shout[2]))
        return render_template('chat_log.html', shouts=shouts, amount=amount)

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('admin', None)
    session.pop('logged_in', None)
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        if session.get('admin', False):
            if request.form['type'] == 'create_user':
                name = request.form['name']
                password = request.form['password']
                # check if checkbox is checked (hehe)
                admin = request.form.getlist('admin')
                admin = admin[0] if len(admin) > 0 else ''
                admin = (admin == 'yes')
                if not new_user(name, password, admin=admin):
                    flash('Name in use, or name and/or password too short.')
                else:
                    flash('User created.')
                return redirect(url_for('settings'))

        if session.get('logged_in', False):
            if request.form['type'] == 'change_password':
                if not change_password(session.get('name', ''), session.get('user_id', ''), request.form['old_password'], request.form['new_password'], request.form['new_password_again']):
                    flash('Something went wrong, password was not changed.')
                else:
                    flash('Password changed.')
                return redirect(url_for('settings'))

    if session.get('logged_in', False):
        return render_template('settings.html')

    return redirect(url_for('index'))

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = connect_db()
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def update_db(query, args=()):
    get_db().cursor().execute(query, args)
    get_db().commit()


def new_user(name, password, admin=False):
    if len(name) < 3 or len(password) < 8 or query_db('select count(*) from users where name = ?', [name], one=True)[0] > 0:
        return False
    update_db('insert into users(name, password, admin) values (?, ?, ?)', [name, bcrypt.generate_password_hash(name + password), admin])
    return True


def change_password(name, user_id, old_password, new_password, new_password_again):
    if new_password == new_password_again and check_password(user_id, old_password):
        update_db('update users set password = ? where user_id = ?', [generate_password_hash(name, new_password), user_id])
        return True
    return False


def check_password(user_id, password):
    user = query_db('select name, password from users where user_id = ?', [user_id], one=True)
    return bcrypt.check_password_hash(user[1], user[0] + password)


def generate_password_hash(name, password):
    return bcrypt.generate_password_hash(name + password)

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[2] == 'debug':
        app.run(debug=True, host='127.0.0.1', port=5000)
    else:
        app.run(debug=False, host=app.config['HOST'], port=app.config['PORT'])
