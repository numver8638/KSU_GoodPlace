#
# views.py
# - 웹 연동 코드. 대부분의 연산은 api에서 이루어지므로 여기서는 html 렌더링만 담당.
#
from flask import Blueprint, render_template
from .auth import required_login

bp = Blueprint('views', __name__, url_prefix='/')


@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/login')
def login():
    return render_template('login.html')


@bp.route('/register')
def register():
    return render_template('register.html')