from flask import render_template, redirect, request, url_for, flash, make_response, current_app
from . import auth
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, OnlineInfo
from .forms import LoginForm, RegistrationForm, LoginMethodForm
from .. import db
from ..email import send_email
from flask import session, request
from weibo import APIClient
from wtforms import BooleanField


@auth.route('/login', methods=['GET', 'POST'])
def login():
    login_info_form = LoginForm()
    login_method_form = LoginMethodForm()
    print login_method_form.method
    if login_info_form.validate_on_submit():
        user = User.query.filter_by(email=login_info_form.email.data).first()
        if user is not None and user.verify_password(login_info_form.password.data):
            login_user(user, login_info_form.remember_me.data)

            loginfo = OnlineInfo(username=user.username, method='Email',
                                 device=(request.remote_addr + request.user_agent.__str__()))
            db.session.add(loginfo)
            db.session.commit()
            print session
            return redirect(url_for('main.user', username=user.username))
        flash('Invalid username or password.')
    return render_template('auth/login.html', login_info_form=login_info_form, login_method_form=login_method_form)


@auth.route('/logout')
@login_required
def logout():
    loginfo = OnlineInfo.query.filter_by(device=(request.remote_addr + request.user_agent.__str__())).first()
    if loginfo is not None:
        db.session.delete(loginfo)
        db.session.commit()
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            user = User(email=form.email.data,
                        username=form.username.data,
                        password=form.password.data)
            db.session.add(user)
            db.session.commit()
        else:
            user.email = form.email.data
            user.password=form.password.data
            db.session.add(user)
            db.session.commit()

        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been send to you.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    logged_in_or_not = is_logged_in(request.remote_addr + request.user_agent.__str__())
    if not logged_in_or_not:
        logout_user()
        print 'logout!!!'
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static' \
            and logged_in_or_not:
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to your address.')
    return redirect(url_for('main.index'))


def get_api_client():
    app = current_app._get_current_object()
    return APIClient(app_key=app.config['APP_KEY'], app_secret=app.config['APP_SECRET'], redirect_uri=app.config['AUTHORIZE_CALLBACK'])


@auth.route("/login/weibo")
def weibo_login():
    client = get_api_client()
    try:
        if request.cookies['is_login'] != 'True':
            raise Exception("Haven't Login")
    except:
        auth_url = client.get_authorize_url()
        print auth_url
        return "<a href=\"%s\">OAuth2</a>" % auth_url
    else:
        access_token = request.cookies.get('access_token')
        expires_in = request.cookies.get('expires_in')
        client.set_access_token(access_token, expires_in)

        if client.is_expires() is True:
            return "access token expired!"
        html = ''
        html = html + "<p>Welcome User %s         <a href=\"logout\">Logout</a></p>" % request.cookies.get(
            'screen_name')
        timeline = client.get.statuses__user_timeline()
        for message in timeline.statuses:
            html += '<p>' + message['text'] + '</p>'
        return html


@auth.route("/callback/authorize")
def callback():
    try:
        code = request.args.get("code")
        print code
        client = get_api_client()
        r = client.request_access_token(code)
        print r
        client.set_access_token(r.access_token, r.expires_in)
        weibo_id = client.get.account__get_uid()
        weibo_account = dict(client.get.users__show(uid=weibo_id.uid))

        # find out whether there's weibo_logged_in user
        user = User.query.filter_by(weibo_id=weibo_id.uid).first()
        weibo_name = weibo_account.get('domain')
        if user is None:
            account_name_exisits = User.query.filter_by(username=weibo_name).first()
            if account_name_exisits is None:
                user = User(username=weibo_name, weibo_id=weibo_id.uid, confirmed=1)
                db.session.add(user)
                db.session.commit()
            else:
                account_name_exisits.weibo_id = weibo_id.uid
                db.session.add(account_name_exisits)
                db.session.commit()

        login_user(user, False)
        print 'user: ', user
        loginfo = OnlineInfo(username=user.username, method='Weibo',
                             device=(request.remote_addr + request.user_agent.__str__()))
        db.session.add(loginfo)
        db.session.commit()
        print session
        return redirect(url_for('main.user', username=user.username))
    except Exception as e:
        return "*** OAuth2 Failed: %s" % str(e)


def is_logged_in(loginfo):
    user = OnlineInfo.query.filter_by(device=loginfo).first()
    if user is None:
        return False
    else:
        return True


@auth.route('/logout/<id>')
@login_required
def logout_sepcific_user(id):
    user = OnlineInfo.query.filter_by(id=id).first()
    try:
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        return "DB operation error: %s" % str(e)
    return redirect(url_for('main.user', username=user.username))


