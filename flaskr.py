# all the import
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash
from contextlib import closing

# configuration
DATABASE = '/tmp/flaskr.db'
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'

# create our little application
app = Flask(__name__)
app.config.from_object(__name__)

app.config.from_envvar('FLASKR_SETTINGS', silent=True)
# silent param tells our app not to report error if SETTINGS file not exists


def connect_db():
    return sqlite3.connect(app.config['DATABASE'])


def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.before_request
def before_request():
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()
    g.db.close()

@app.route('/')
def show_entries():
    cur = g.db.execute('select title, text from entries order by id desc')
    entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    g.db.execute('insert into entries (title, text) values (?, ?)',
                 [request.form['title'], request.form['text']])
    g.db.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        current_username = request.form['username']
        current_password = request.form['password']
        cur = g.db.execute(
            'select count(id), passwd from users where usrname = ?', (current_username,))
        data_dic = cur.fetchall()
        if 0 == int(data_dic[0][0]):
            error = 'Invalid username'
        elif current_password != data_dic[0][1]:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_entries'))

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in')
    flash('You were logged out')
    return redirect(url_for('show_entries'))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    error = None
    if request.method == 'POST':
        current_username = request.form['username']
        current_password = request.form['password']
        # print current_username
        cur = g.db.execute(
            "select count(id) from users where usrname = ? ", (current_username,))
        id_counter = int(cur.fetchall()[0][0])
        if id_counter >= 1:
            flash('already exists!')
        else:
            g.db.execute('insert into users (usrname, passwd) values (?, ?)',
                [current_username, current_password])
            g.db.commit()
            flash('sign in succeeded!')
            return redirect(url_for('login'))
    return render_template('signin.html', error=error)


# danerous! shall be removed after finished!
@app.route('/testdb')
def test_db():
    cur = g.db.execute(
            'select usrname, passwd from users')
    users = [dict(username=row[0], password=row[1]) for row in cur.fetchall()]
    print users
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
