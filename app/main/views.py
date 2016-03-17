from flask import render_template, session, redirect, url_for, current_app, request
from .. import db
from ..models import User, OnlineInfo
from ..email import send_email
from . import main
from .forms import NameForm
from flask_login import login_required


@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            session['known'] = False
            if current_app.config['FLASKY_ADMIN']:
                send_email(current_app.config['FLASKY_ADMIN'], 'New User',
                           'email/new_user', user=user)
        else:
            session['known'] = True
        session['name'] = form.name.data
        return redirect(url_for('.index'))
    return render_template('index.html',
                           form=form, name=session.get('name'),
                           known=session.get('known', False))


@main.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'


@main.route('/user/<username>')
@login_required
def user(username):
    users = OnlineInfo.query.filter_by(username=username).all()
    user_id = [x.id for x in users]
    user_device = [x.device for x in users]
    users = dict(zip(user_id, user_device))
    self_info = request.remote_addr + str(request.user_agent)

    account = User.query.filter_by(username=username).first()
    email_bool, weibo_bool = False, False
    if account.email is not None and account.email != '':
        email_bool = True
    if account.weibo_id is not None and account.weibo_id !='':
        weibo_bool = True
    register_status = dict(zip(['Email', 'Weibo'], [email_bool, weibo_bool]))
    print register_status
    return render_template('user.html', self_info=self_info, users=users, register_status=register_status)


@main.route('/tmp')
def tmp():
    return render_template('tmp.html')


