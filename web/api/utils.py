#
# utils.py
# - 유틸리티 함수들이 정의된 모듈.
#
from flask import request
from werkzeug.exceptions import BadRequest


def get_request_argument(name, default=None, is_required=False, type=None):
    """
    GET 인자를 가져옵니다.

    정의되지 않은 필수 인자이거나 요구하는 타입과 다른 경우 `400 - BadRequest` 반환.  
    """
    value = request.args.get(name, default)

    if is_required and value is None:
        raise BadRequest('Omitted required argument \'{0}\'.'.format(name))

    if type is not None:
        try:
            return type(value)
        except (ValueError, TypeError):
            raise BadRequest('Invalid argument type of \'{0}\'.'.format(name))
    else:
        return value


def get_post_argument(name, default=None, is_required=False, type=None):
    """
    POST 인자를 가져옵니다. POST 인자 또는 JSON 둘 다 수용합니다.

    정의되지 않은 필수 인자이거나 요구하는 타입과 다른 경우 `400 - BadRequest` 반환.    
    """
    if request.json is None and request.form is None:
        raise BadRequest('Omitted request body.')

    data = request.json if request.json is not None else request.form
    value = data.get(name, default)

    if is_required and value is None:
        raise BadRequest('Omitted required argument \'{0}\'.'.format(name))

    if type is not None:
        try:
            return type(value)
        except (ValueError, TypeError):
            raise BadRequest('Invalid argument type of \'{0}\'.'.format(name))
    else:
        return value