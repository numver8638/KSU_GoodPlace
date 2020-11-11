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

    from .views import main_view, login_view, register_view

    app.register_blueprint(main_view.bp)
    app.register_blueprint(login_view.bp)
    app.register_blueprint(register_view.bp)

    print(app.config['CLIENT_ID'])

    @app.errorhandler(404)
    def error_handler(error):
        return render_template('error.html', error_code=error.code, error_description=error.description)

    return app

app = create_app()