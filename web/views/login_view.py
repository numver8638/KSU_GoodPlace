#
# login_view.py
# - 로그인 페이지 관련 코드
#
from flask import Blueprint, render_template

bp = Blueprint('login_view', __name__, url_prefix='/login')

@bp.route('/')
def login():
    return render_template('login.html')