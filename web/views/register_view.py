from flask import Blueprint, render_template

bp = Blueprint('register_view', __name__, url_prefix='/register')

@bp.route('/')
def register():
    return render_template('register.html')