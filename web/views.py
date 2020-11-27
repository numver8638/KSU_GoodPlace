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
    user = User.get_current_user()

    return render_template('index.html', user=user)


@bp.route('/login')
def login():
    user = User.get_current_user()

    if user.is_annonymous():
        return render_template('login.html')
    else:
        return render_template('info.html', message='Already logged in.')

@bp.route('/logout')
def logout():
    user = User.get_current_user()

    # Invalidate token id.
    if not user.is_annonymous():
        user.token_id = None

    # 메인 화면으로 리디렉트
    response = redirect(url_for('views.index'))

    # 쿠키 무효화
    response.set_cookie('__USER_TOKEN', '', max_age=0)
    response.set_cookie('__USER_ID', '', max_age=0)

    return response

@bp.route('/register')
def register():
    user = User.get_current_user()

    if user.is_annonymous():
        return render_template('register.html')
    else:
        return render_template('info.html', message='Cannot register in login state.')


@bp.route('/user')
@required_login
def user(user):
    return render_template('user.html', user=user)


@bp.route('/admin')
@required_login('admin')
def admin(user):
    return render_template('admin.html', user=user)