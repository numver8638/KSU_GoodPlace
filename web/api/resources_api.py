#
# resources_api.py
# - 사진 업로드 같은 리소스를 처리하는 API.
#
import os

from Crypto import Random
from flask import request, url_for, current_app, send_file
from flask_restx import Namespace, Resource
from werkzeug.exceptions import BadRequest, NotFound
from werkzeug.utils import secure_filename

from ..user import required_login

api = Namespace('resources')

# 허용하는 파일 확장자 목록.
# 현재 jpeg, png 2가지의 사진 파일만 허용.
ALLOWED_FILE_EXTENSIONS = [
    'jpg', 'jpeg', 'png'
]


def is_valid_url(url):
    """
    정상적인 URL인지 판단하는 함수. 이 서버에서 생성한 URL이 맞다면 `True`, 아니면 `False`를 반환.
    """
    return True


def allowed_file(filename):
    """
    허용하는 파일인지 판단하는 함수.
    파일의 확장자가 `ALLOWED_FILE_EXTENSIONS`에 정의된 확장자라면 `True`를, 확장자가 없거나 정의되지 않은 확장자라면 `False`를 반환.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS


def _generate_random_name():
    """
    랜덤 파일 이름을 생성하는 함수. 파일 이름 충돌 방지와 보안을 위해 사용.
    """
    while True:
        rand = Random.new().read(16)
        name = "".join([ "{0:02x}".format(b) for b in rand ])

        if not os.path.exists(os.path.join(current_app.config['UPLOAD_ROOT'], name)):
            return name


@api.route('/<string:resource_id>')
class ResourcesAPI(Resource):
    def get(self, resource_id):
        """
        `GET /api/resources/<resource_id>`

        지정된 id를 가진 리소스를 가져오는 메서드.

        존재하지 않는 리소스인 경우 `404 - NotFound` 반환. 
        """
        path = os.path.join(current_app.config['UPLOAD_ROOT'], secure_filename(resource_id))

        if not os.path.exists(path):
            raise NotFound('resource not found.')
        else:
            return send_file(path)


@api.route('/upload')
class UploadAPI(Resource):
    @required_login
    def post(self):
        """
        `POST /api/resources/upload`

        파일을 업로드 하는 메서드. 허용하는 파일은 `ALLOWED_FILE_EXTENSIONS` 참고.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        파일을 업로드 하지 않거나, 허용되지 않은 파일을 업로드 할 경우 `400 - BadRequest` 반환.
        정상적으로 업로드 되었을 경우 `message`과 `url`이 JSON으로 반환.
        """
        if request.files is None:
            raise BadRequest('File not uploaded.')

        file = request.files.get('file', default=None)

        if file is None:
            raise BadRequest("Omitted required data 'file'.")

        if file.filename == '':
            raise BadRequest('File not uploaded.')

        if not allowed_file(file):
            raise BadRequest('Not allowed file type.')

        filename = _generate_random_name()
        file.save(os.path.join(current_app.config['UPLOAD_ROOT'], filename))

        return jsonify(message='Success', url=url_for('api.resources', filename=filename))