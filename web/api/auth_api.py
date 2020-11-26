#
# auth_api.py
# - 사용자 인증과 관련된 작업을 담당하는 API.
#
from flask_restx import Resource, Namespace
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized, RequestTimeout
from Crypto.Hash import SHA256, BLAKE2s
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from flask import current_app, jsonify
import json
import base64
import time

from . import utils
from ..user import required_login, User, InvalidCredential, UserIDConflict, check_user_id_conflict


api = Namespace('/auth')


def _generate_cipher():
    secret = current_app.config['ENCRYPT_SECRET_KEY']
    # Generate initial vector from hash of ENCRYPT_SECRET_KEY.
    iv = BLAKE2s.new(digest_bits=128).update(secret).digest()
    
    return AES.new(secret, AES.MODE_CBC, iv)


def _generate_token(request_id:str):
    """
    사용자 요청 id 를 기반으로 인증 토큰을 발행하는 함수.

    토큰 내부 데이터로
        - 사용자가 보낸 데이터를 복호화 하는 개인키
        - 사용자의 요청 id
        - 토큰의 발행 시간
        - 토큰의 해쉬값
    이 JSON 형태로 저장되고, 이것을 다시 ENCRYPT_SECRET_KEY로
    AES 암호화 한 뒤 BASE64 인코딩으로 발급.
    """
    rsa = RSA.generate(2048)

    pubkey = rsa.publickey().export_key(format='DER')
    prikey = rsa.export_key(format='DER')

    public_key = base64.b64encode(pubkey).decode('utf-8')
    private_key = base64.b64encode(prikey)
    issue_time = str(int(time.time()))

    h = SHA256.new()
    h.update(request_id.encode('utf-8'))
    h.update(private_key)
    h.update(issue_time.encode('utf-8'))

    token = {
        'request_id': request_id,
        'private_key': private_key.decode('utf-8'),
        'issue_at': issue_time,
        'signature': h.hexdigest()
    }

    cipher = _generate_cipher()
    data = pad(json.dumps(token).encode('utf-8'), AES.block_size)
    encrypted_token = cipher.encrypt(data)

    return { 'key': public_key, 'token': base64.b64encode(encrypted_token).decode('utf-8') }


def _get_token_data(token_: str):
    """
    발급한 토큰에서 다시 데이터를 복호화/검증 하는 함수.

    토큰의 해쉬값이 올바른지, 발급시간으로부터 30초 이내인지 등을 확인.
    """
    try:
        encrypted_token = base64.b64decode(token_.encode('utf-8'))

        cipher = _generate_cipher()
        data = unpad(cipher.decrypt(encrypted_token), AES.block_size)
        token = json.loads(data.decode('utf-8'))

        h = SHA256.new()
        h.update(token['request_id'].encode('utf-8'))
        h.update(token['private_key'].encode('utf-8'))
        h.update(token['issue_at'].encode('utf-8'))

        # Check token is not modified
        if h.hexdigest() != token['signature']:
            raise ValueError()

        # Check token is not expired
        if int(token['issue_at']) + 30 < int(time.time()):
            raise RequestTimeout('Token is expired.')

        return token
    except (KeyError, ValueError) as e:
        current_app.logger.exception(e)
        raise BadRequest('Invalid token.')


def _verify_and_get_data(encrypted_data, token):
    """
    유저가 보낸 데이터를 복호화하고 적절한 요청인지 확인하는 함수.

    적절한 요청인 경우 복호화된 데이터가 반환되고 유효하지 않을 시 `werkzeug.exceptions.BadRequest` 예외가 발생.
    """
    try:
        key = base64.b64decode(token['private_key'].encode('utf-8'))

        rsa = RSA.import_key(key)
        cipher = PKCS1_v1_5.new(rsa)
        sentinel = Random.new().read(16)
        data = cipher.decrypt(base64.b64decode(encrypted_data.encode('utf-8')), sentinel)
        
        if data == sentinel:
            raise ValueError()
        else:
            data = data.decode('utf-8')

        json_data = json.loads(data)

        if json_data['request_id'] != token['request_id']:
            raise BadRequest('request - token mismatch.')
        
        return json_data
    except (KeyError, ValueError, UnicodeError) as e:
        current_app.logger.exception(e)
        raise BadRequest('Data corrupted.')


@api.route('/check_id/<string:id>')
class CheckIDAPI(Resource):
    def get(self, id):
        """
        GET /api/auth/check_id/<id>

        주어진 아이디가 이미 사용중인지 판단.
        `conflict`가 `True`인 경우 이미 사용중, `False`인 경우 사용 가능.
        """
        return jsonify(message='Success', conflict=check_user_id_conflict(id))


@api.route('/register')
class RegisterAPI(Resource):
    def get(self):
        """
        GET /api/auth/register

        회원가입 요청 토큰 발급.

        `request_id` 요구. 없을시 `400 - BadRequest` 반환.

        parameters:
            - request_id: 요청 확인용 무작위 문자열.

        returns:
            - key: RSA-2048 암호화 키. 회원가입 데이터 암호화시 사용.
            - token: 회원가입 요청 토큰.
        """
        request_id = utils.get_request_argument('request_id', is_required=True)
        return _generate_token(request_id)

    def post(self):
        """
        POST /api/auth/register

        회원가입 요청.
        
        회원 데이터 `data`와 `GET` 메서드에서 발급받은 `token`이 요구.

        정상적으로 처리 된 경우 `201 - Created` 반환.

        아래와 같은 경우 `400 - BadRequest`가 반환.
        - 요구되는 데이터가 없는 경우
        - 토큰의 유효시간(발급후 30초)이 지난 경우
        - 유효하지 않은 토큰인 경우
        - 토큰과 `request_id`가 일치 하지 않는 경우
        - 발급된 토큰과 다른 `key`로 암호화 한 경우
        - 이미 유저 아이디가 사용중인 경우

        parameters:
            - data: 회원가입 데이터.
                - request_id: `GET` 요청시와 같은 `request_id`.
                - user_id: 유저의 아이디.
                - user_pw: 유저의 SHA-256 hashed 비밀번호.
                - user_name: 유저의 이름
                - user_nickname: 유저의 별명.
                - user_profile: 유저의 프로파일 사진 URL.
            - token: `GET` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        token = _get_token_data(encrypted_token)
        data = _verify_and_get_data(encrypted_data, token)

        # Verified area
        try:
            User.create_new_user(
                data['user_id'], data['user_pw'], data['user_name'], data['user_nickname'], data['user_profile']
            )
        except KeyError:
            raise BadRequest('Omitted required data.')
        except UserIDConflict:
            raise BadRequest('User ID conflict.')
        else:
            return { 'message': 'Created' }, 201


@api.route('/login')
class LoginAPI(Resource):
    def get(self):
        """
        GET /api/auth/login

        로그인 요청 토큰 발급.

        `request_id` 요구. 없을시 `400 - BadRequest` 반환.

        parameters:
            - request_id: 요청 확인용 무작위 문자열.

        returns:
            - key: RSA-2048 암호화 키. 로그인 데이터 암호화시 사용.
            - token: 로그인 요청 토큰.
        """
        request_id = utils.get_request_argument('request_id', is_required=True)
        return _generate_token(request_id)
    

    def post(self):
        """
        POST /api/auth/register

        로그인 요청.
        
        로그인 데이터 `data`와 `GET` 메서드에서 발급받은 `token`이 요구.

        아래와 같은 경우 `400 - BadRequest`가 반환.
        - 요구되는 데이터가 없는 경우
        - 토큰의 유효시간(발급후 30초)이 지난 경우
        - 유효하지 않은 토큰인 경우
        - 토큰과 `request_id`가 일치 하지 않는 경우
        - 발급된 토큰과 다른 `key`로 암호화 한 경우
        - 없는 아이디거나 아이디와 일치하지 않는 비밀번호인 경우

        parameters:
            - data: 로그인 데이터.
                - request_id: `GET` 요청시와 같은 `request_id`.
                - user_id: 유저의 아이디.
                - user_pw: 유저의 SHA-256 hashed 비밀번호.
            - token: `GET` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.
            - token: 유저 인증 토큰.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        token = _get_token_data(encrypted_token)
        data = _verify_and_get_data(encrypted_data, token)

        # Verified area
        user: User

        try:
            user = User.from_id_pw(data['user_id'], data['user_pw'])
        except KeyError:
            raise BadRequest('Omitted required data.')
        except InvalidCredential:
            raise Forbidden('Unknown user or id/pw mismatch.')
        else:
            return { 'message': 'Success', 'user_id': user.id, 'token': user.to_token() }


@api.route('/logout')
@api.route('/logout/<uid>')
class LogoutAPI(Resource):
    @required_login
    def get(self, user, uid=None):
        """
        GET /api/auth/logout
        GET /api/auth/logout/<uid>

        유저 로그아웃.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        본인 계정 또는 권한 요구: `admin.auth.logout`. 권한이 없는 경우 `403 - Forbidden` 반환.

        <uid>가 생략된 경우 로그인한 본인이, 생략되지 않은 경우 지정된 유저가 로그아웃.
        <uid>가 로그인한 유저와 다른 유저 고유 번호일 경우 상기한 권한을 요구함.

        TODO: 토큰 특성상 한번 발급하면 로그아웃 하기가 어려움. 토큰을 무효화 하는 방법 필요.
        """
        if uid is None or user.uid == uid:
            # Process logout
            pass
        elif user.has_permission('admin.auth.logout'):
            # Process force logout
            pass
        else:
            raise Forbidden('Operation not permitted.')


@api.route('/update_password')
class UpdatePasswordAPI(Resource):
    def get(self):
        """
        GET /api/auth/update_password

        비밀번호 변경 요청 토큰 발급.

        `request_id` 요구. 없을시 `400 - BadRequest` 반환.

        정상인 경우 `key`와 `token` 발급.
        `key`로 데이터를 암호화, 데이터를 전송할 때 `token`과 같이 전송.

        parameters:
            - request_id: 요청 확인용 무작위 문자열.

        returns:
            - key: RSA-2048 암호화 키. 비밀번호 데이터 암호화시 사용.
            - token: 비밀번호 변경 요청 토큰.
        """
        request_id = utils.get_request_argument('request_id', is_required=True)
        return _generate_token(request_id)
    
    @required_login
    def post(self, user):
        """
        POST /api/auth/update_password

        비밀번호 변경 요청.
        
        비밀번호 데이터 `data`와 `GET` 메서드에서 발급받은 `token`이 요구.

        아래와 같은 경우 `400 - BadRequest`가 반환.
        - 요구되는 데이터가 없는 경우
        - 토큰의 유효시간(발급후 30초)이 지난 경우
        - 유효하지 않은 토큰인 경우
        - 토큰과 `request_id`가 일치 하지 않는 경우
        - 발급된 토큰과 다른 `key`로 암호화 한 경우

        아래와 같은 경우 `403 - Forbidden`이 반환.
        - 전 비밀번호가 현재 로그인된 유저의 비밀번호와 다른 경우.

        parameters:
            - data: 로그인 데이터.
                - request_id: `GET` 요청시와 같은 `request_id`.
                - old_pw: 유저의 SHA-256 hashed 전 비밀번호.
                - new_pw: 유저의 SHA-256 hashed 새로운 비밀번호.
            - token: `GET` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.

        TODO: 토큰의 특성상 비밀번호 변경 전 발급된 토큰들도 유효성을 가짐. 이 토큰들을 무효화할 방법 필요.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        token = _get_token_data(encrypted_token)
        data = _verify_and_get_data(encrypted_data, token)

        # Verified area
        try:
            user.update_password(data['old_pw'], data['new_pw'])
        except KeyError:
            raise BadRequest('Omitted required data.')
        except InvalidCredential:
            raise Forbidden('User/password mismatch.')
        else:
            return { 'message': 'Success' }