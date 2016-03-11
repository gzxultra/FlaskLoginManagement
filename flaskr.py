# all the import
import sqlite3
import re
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash
from contextlib import closing
from flask_bootstrap import Bootstrap

# configuration
DATABASE = '/tmp/flaskr.db'
DEBUG = True
SECRET_KEY = '\xb1\xdd\x9b\xbbG\x90\xa5\xfb\x11\x8ai\xca\xd6\xf3!3DO\xbcG@\xf2\x8e\x84'
# USERNAME = 'admin'
# PASSWORD = 'default'

# create our little application
app = Flask(__name__)
app.config.from_object(__name__)
bootstrap = Bootstrap(app)

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

@app.route('/user/<name>')
def user(name):
    cur = g.db.execute(
        'select location from onlineInfo where usrname = ?', (name,))
    user = [dict(location=row[0]) for row in cur.fetchall()]
    print user
    return render_template('user.html', users=user)


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
        users_already_logged_in = int(data_dic[0][0])
        if 0 == users_already_logged_in:
            error = 'Invalid username'
        elif current_password != data_dic[0][1]:
            error = 'Invalid password'
        else:
            client_already_logged_in = list_logged_in_client(current_username)
            g.db.execute('insert into onlineInfo (usrname, location) values(?, ?)',
                               [current_username, str(int(client_already_logged_in)+1)])
            g.db.commit()
            session['logged_in'] = True
            session['info'] = (current_username, int(client_already_logged_in)+1)
            flash('You were logged in')

            return redirect(url_for('user', name=current_username))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    print session
    information = session.get('info')
    print information
    session.clear()
    print session
    g.db.execute('delete from onlineInfo where usrname=? and location=?', (information[0], information[1]))
    g.db.commit()
    flash('You were logged out')
    return redirect(url_for('show_entries'))


def offline(name, id):
    cur = g.db.execute('delete from onlineInfo where usrname=? and location=?', (name, id))
    g.db.commit()




@app.route('/signin', methods=['GET', 'POST'])
def signin():
    error = None
    if request.method == 'POST':
        current_username = request.form['username']
        current_password = request.form['password']
        if validate_email(current_username) is False:
            error = 'Invalid username'
            return render_template('signin.html', error=error)
        if validate_password(current_password) is False:
            error = 'Invalid password'
            return render_template('signin.html', error=error)
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


def validate_email(email):
    if re.match('^\w+[\w.]*@[\w.]+\.\w+$', email) is not None:
        return True
    else:
        return False


def validate_password(password):
    if re.match('^[0-9_a-zA-Z]{6,20}$', password) is not None:
        return True
    else:
        return False


def list_logged_in_client(current_username):
    print current_username
    cur = g.db.execute(
            # 'select count(id) from onlineInfo where usrname = ?', (current_username,))
            'select location, count(id) from onlineInfo where usrname = ?', (current_username,))
    online = cur.fetchall()
    print online
    client_already_logged_in = online[0][1]
    print client_already_logged_in
    return client_already_logged_in
    # print cur.fetchall()[0][0]


# danerous! shall be removed after finished!
@app.route('/testdb')
def test_db():
    cur = g.db.execute(
            'select usrname, passwd from users')
    users = [dict(username=row[0], password=row[1]) for row in cur.fetchall()]
    print users
    return redirect(url_for('login'))


# danerous! shall be removed after finished!
@app.route('/testlist')
def test_list():
    offline('b@b.com', '1')
    return render_template('test.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0')
