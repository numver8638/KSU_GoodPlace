#
# auth_api.py
# - 사용자 인증과 관련된 작업을 담당하는 API.
#
from flask_restx import Resource, Namespace
from werkzeug.exceptions import BadRequest, Forbidden
from flask import current_app, jsonify

from . import utils
from ..user import required_login, User, InvalidCredential, UserIDConflict, check_user_id_conflict


api = Namespace('/auth')


@api.route('/request_token')
class RequestTokenAPI(Resource):
    def get(self):
        """
        GET /auth/request_token

        인증 요청이 필요한 모든 요청에 토큰을 발급.

        `request_id` 요구. 없을시 `400 - BadRequest` 반환.

        parameters:
            - request_id: 요청 확인용 무작위 문자열.

        returns:
            - key: RSA-2048 암호화 키. 데이터 암호화시 사용.
            - token: 인증 토큰.
        """
        request_id = utils.get_request_argument('request_id', is_required=True)
        return utils.generate_token(request_id, current_app.config['ENCRYPT_SECRET_KEY'])


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
    def post(self):
        """
        POST /api/auth/register

        회원가입 요청.
        
        회원 데이터 `data`와 `/auth/request_token` 메서드에서 발급받은 `token`이 요구.

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
                - request_id: `/auth/request_token` 요청시와 같은 `request_id`.
                - user_id: 유저의 아이디.
                - user_pw: 유저의 SHA-256 hashed 비밀번호.
                - user_name: 유저의 이름
                - user_nickname: 유저의 별명.
                - user_profile: 유저의 프로파일 사진 URL.
            - token: `/api/auth/request_token` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        # Verified area
        try:
            data = utils.verify_and_get_data(encrypted_data, encrypted_token, current_app.config['ENCRYPT_SECRET_KEY'])

            User.create_new_user(
                data['user_id'], data['user_pw'], data['user_name'], data['user_nickname'], data['user_profile']
            )
        except (utils.InvalidToken, utils.CorruptedData) as e:
            raise BadRequest(str(e))
        except KeyError:
            raise BadRequest('Omitted required data.')
        except UserIDConflict:
            raise BadRequest('User ID conflict.')
        else:
            return { 'message': 'Created' }, 201


@api.route('/login')
class LoginAPI(Resource):
    def post(self):
        """
        POST /api/auth/register

        로그인 요청.
        
        로그인 데이터 `data`와 `/auth/request_token` 메서드에서 발급받은 `token`이 요구.

        아래와 같은 경우 `400 - BadRequest`가 반환.
        - 요구되는 데이터가 없는 경우
        - 토큰의 유효시간(발급후 30초)이 지난 경우
        - 유효하지 않은 토큰인 경우
        - 토큰과 `request_id`가 일치 하지 않는 경우
        - 발급된 토큰과 다른 `key`로 암호화 한 경우
        - 없는 아이디거나 아이디와 일치하지 않는 비밀번호인 경우

        parameters:
            - data: 로그인 데이터.
                - request_id: `/auth/request_token` 요청시와 같은 `request_id`.
                - user_id: 유저의 아이디.
                - user_pw: 유저의 SHA-256 hashed 비밀번호.
            - token: `/api/auth/request_token` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.
            - token: 유저 인증 토큰.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        # Verified area
        user: User

        try:
            data = utils.verify_and_get_data(encrypted_data, encrypted_token, current_app.config['ENCRYPT_SECRET_KEY'])

            user = User.from_id_pw(data['user_id'], data['user_pw'])
        except (utils.InvalidToken, utils.CorruptedData) as e:
            raise BadRequest(str(e))
        except KeyError:
            raise BadRequest('Omitted required data.')
        except InvalidCredential:
            raise Forbidden('Unknown user or id/pw mismatch.')
        else:
            token = user.to_token()

            # 웹과 API를 모두 지원하기 위해 JSON과 쿠키를 동시에 전송.
            response = jsonify(message='Success', user_id=user.uid, token=token)
            response.set_cookie('__USER_TOKEN', token, httponly=True)
            response.set_cookie('__USER_ID', user.uid)

            return response


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

        토큰 고유 번호를 리셋시켜 다른 토큰들을 무효화시킴.
        """
        if uid is None or user.uid == uid:
            user.token_id = None
        elif user.has_permission('admin.auth.logout'):
            # Process force logout
            target_user = User.from_uid(uid)

            if target_user.is_annonymous():
                raise NotFound("User UID %s is not found." % uid)
            else:
                target_user.token_id = None
        else:
            raise Forbidden('Operation not permitted.')


@api.route('/update_password')
@api.route('/update_password/<uid>')
class UpdatePasswordAPI(Resource):
    @required_login
    def post(self, user, uid=None):
        """
        POST /api/auth/update_password

        비밀번호 변경 요청.
        
        비밀번호 데이터 `data`와 `/auth/request_token` 메서드에서 발급받은 `token`이 요구.

        아래와 같은 경우 `400 - BadRequest`가 반환.
        - 요구되는 데이터가 없는 경우
        - 토큰의 유효시간(발급후 30초)이 지난 경우
        - 유효하지 않은 토큰인 경우
        - 토큰과 `request_id`가 일치 하지 않는 경우
        - 발급된 토큰과 다른 `key`로 암호화 한 경우

        아래와 같은 경우 `403 - Forbidden`이 반환.
        - 전 비밀번호가 현재 로그인된 유저의 비밀번호와 다른 경우.

        parameters:
            - uid: 대상 유저의 고유 번호.
                   없을 경우 자신의 비밀번호를 변경하는 것으로 간주.
            - data: 로그인 데이터.
                - request_id: `/auth/request_token` 요청시와 같은 `request_id`.
                - old_pw: 유저의 SHA-256 hashed 전 비밀번호.
                - new_pw: 유저의 SHA-256 hashed 새로운 비밀번호.

                또는

                - request_id: `/auth/request_token` 요청시와 같은 `request_id`.
                - admin_pw: 관리자 유저의 SHA-256 hashed 비밀번호.
                - new_pw: 대상 유저의 SHA-256 hashed 새로운 비밀번호.
            - token: `/api/auth/request_token` 메서드에서 발급받은 `token`.

        returns:
            - message: 상태 메세지.
        """
        encrypted_data = utils.get_post_argument('data', is_required=True)
        encrypted_token = utils.get_post_argument('token', is_required=True)

        try:
            data = utils.verify_and_get_data(encrypted_data, encrypted_token, current_app.config['ENCRYPT_SECRET_KEY'])

            if uid is None or user.uid == uid:
                # uid 가 정의되지 않았거나 자신의 uid인 경우
                user.update_password(data['old_pw'], data['new_pw'])

            elif user.has_permission('admin.auth.update_password'):
                # 다른 유저의 uid이고 권한이 있는 경우
                target_user = User.from_uid(uid)

                if target_user.is_annonymous():
                    raise NotFound('User UID %s is not found.' % uid)
                
                elif user.check_password(data['admin_pw']):
                    target_user.set_password(data['new_pw'])
                
                else:
                    raise InvalidCredential()

            else:
                raise Forbidden('Operation not permitted.')

        except (utils.InvalidToken, utils.CorruptedData) as e:
            raise BadRequest(str(e))

        except KeyError:
            raise BadRequest('Omitted required data.')

        except InvalidCredential:
            raise Forbidden('User/password mismatch.')

        else:
            return { 'message': 'Success' }