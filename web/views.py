#
# views.py
# - 웹 연동 코드. 대부분의 연산은 api에서 이루어지므로 여기서는 html 렌더링만 담당.
#
from flask import Blueprint, render_template, url_for, redirect, request, make_response
from werkzeug.exceptions import BadRequest
from .user import required_login, User

bp = Blueprint('views', __name__, url_prefix='/')


@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/login')
def login():
    user = User.get_current_user()

    if user.is_annonymous():
        return render_template('login.html')
    else:
        return render_template('info.html', message='')


@bp.route('/register')
def register():
    user = User.get_current_user()

    if user.is_annonymous():
        return render_template('register.html')
    else:
        return render_template('info.html', message='')


@bp.route('/users/<user_id>')
@required_login
def user(user, user_id):
    return render_template('user.html')


@bp.route('/admin')
@required_login('admin')
def admin(user):
    return render_template('admin.html')