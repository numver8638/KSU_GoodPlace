import os
from flask import Flask, render_template
from werkzeug.exceptions import HTTPException

def create_app(test_config=None):
    path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__, instance_relative_config=True, instance_path=path)

    if test_config is None:
        app.config.from_json('config.json')
    else:
        app.config.from_mapping(test_config)

    # Register views
    from . import views
    app.register_blueprint(views.bp)

    @app.errorhandler(Exception)
    def error_handler(error):
        if isinstance(error, HTTPException):
            return render_template('error.html', error_code=error.code, error_description=error.description)
        else:
            return render_template('error.html', error_code=500, error_description='Internal Error')
    return app

app = create_app()