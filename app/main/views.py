from flask import render_template, session, redirect, url_for, current_app, request
from .. import db
from ..models import User, OnlineInfo
from ..email import send_email
from . import main
from .forms import NameForm
from flask_login import login_required, current_user


@main.route('/')
def index():
    username = current_user.username
    return render_template('index.html', name=username)


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


