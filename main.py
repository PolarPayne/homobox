from flask import Flask, session, redirect, url_for, render_template, request, g
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
    if request.method == 'POST':
        # first time setup
        if request.form['type'] == 'setup' and query_db('select count(*) from users', one=True)[0] == 0:
            name = request.form['name']
            password = request.form['password']
            update_db('insert into users(name, password, admin) values (?, ?, ?)', [name, bcrypt.generate_password_hash(name + password), True])
            return redirect(url_for('index'))

        # login
        if request.form['type'] == 'login':
            name = request.form['name']
            password = request.form['password']
            # validate the user
            user = query_db('select user_id, name, password, admin from users where name = ?', [name], one=True)
            if check_password(user[0], password):
                session['user_id'] = user[0]
                session['name'] = user[1]
                session['admin'] = bool(user[3])
                session['logged_in'] = True
                return redirect(url_for('index'))

        if session['logged_in']:
            if request.form['type'] == 'shout':
                update_db('insert into shouts(user_id, shout, post_time) values (?, ?, datetime(\'now\', \'localtime\'))', [session['user_id'], request.form['content']])
                return redirect(url_for('index'))

    # first time setup
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

    shouts = []
    for shout in query_db('select name, shout, strftime(\'%Y-%m-%d %H:%M\', post_time) from users natural join shouts order by shout_id desc limit 15'):
        shouts.insert(0, (shout[0], shout[1], shout[2]))
    return render_template('index.html', shouts=shouts)


@app.route('/chat_log')
@app.route('/chat_log/<int:amount>')
def chat_log(amount=50):
    if session['logged_in']:
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
        if session['admin']:
            if request.form['type'] == 'create_user':
                name = request.form['name']
                password = request.form['password']
                admin = request.form.getlist('admin')
                admin = admin[0] if len(admin) > 0 else ''
                admin = (admin == 'yes')
                update_db('insert into users(name, password, admin) values (?, ?, ?)', [name, generate_password_hash(name, password), admin])
                return redirect(url_for('settings'))

        if session['logged_in']:
            if request.form['type'] == 'change_password':
                old_password = request.form['old_password']
                new_password = request.form['new_password']
                new_password_again = request.form['new_password_again']
                if new_password == new_password_again and check_password(session['user_id'], old_password):
                    update_db('update users set password = ? where user_id = ?', [generate_password_hash(session['name'], new_password), session['user_id']])
                return redirect(url_for('settings'))

    return render_template('settings.html')


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
