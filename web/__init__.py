import os
from flask import Flask, render_template, request, make_response, g
from werkzeug.exceptions import HTTPException
from flask.json import jsonify
import base64
from .translate import translate as _

def create_app(test_config=None):
    path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__, instance_relative_config=True, instance_path=path)

    if test_config is None:
        app.config.from_json('config.json')
    else:
        app.config.from_mapping(test_config)

    app.config['ENCRYPT_SECRET_KEY'] = base64.b64decode(app.config['ENCRYPT_SECRET_KEY'].encode('utf-8'))

    # Upload path
    upload_root = os.path.join(path, 'Uploads')
    if not os.path.exists(upload_root):
        os.mkdir(upload_root)

    app.config['UPLOAD_ROOT'] = upload_root

    # Limit maximum upload size to 4MB.
    app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

    # Register blueprints
    from . import views, api

    app.register_blueprint(views.bp)
    app.register_blueprint(api.bp)

    @app.errorhandler(Exception)
    def error_handler(error):
        app.logger.exception(error)

        code: int
        desc: str

        if isinstance(error, HTTPException):
            code = error.code
            desc = error.description
        else:
            code = 500
            desc = 'Internal Error'
        
        if request.path.startswith('/api/'):
            response = jsonify(message=desc)
            response.status_code = code

            return response
        else:
            return render_template('error.html', error_code=code, error_description=desc), code

    @app.teardown_appcontext
    def destory_db(error):
        db = getattr(g, '_database', None)

        if db is not None:
            db.close()

    return app

app = create_app()