from flask import Blueprint
from flask_restx import Api

def create_api():
    bp = Blueprint('api', __name__, url_prefix='/api')

    api = Api(bp)

    from . import auth_api, post_api, user_api, resources_api

    # Register namespaces
    api.add_namespace(auth_api.api)
    api.add_namespace(post_api.api)
    api.add_namespace(user_api.api)
    api.add_namespace(resources_api.api)

    return bp

bp = create_api()