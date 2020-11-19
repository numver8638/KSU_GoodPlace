#
# users_api.py
# - 유저 관리를 담당하는 API.
#
from flask import jsonify
from flask_restx import Resource, Namespace
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from . import resources_api, utils 
from .. import database
from ..user import required_login, User, InvalidPermission

api = Namespace('/users')

@api.route('')
class UsersAPI(Resource):
    @required_login(required_perm='admin.users')
    def get(self, user):
        """
        GET /api/users

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `admin.users`. 권한이 없는 경우 `403 - Forbidden` 반환.

        현재 등록된 유저의 목록을 가져옵니다.
        개인정보 보호를 위해 유저 고유 번호, 닉네임과 프로필사진 URL만 가져옵니다.

        parameters:
            - [optional]count: 유저의 최대 개수. 기본값: 20
            - [optional]start: 시작 index. 기본값: 0

        returns:
            - message: 상태 메세지.
            - start: 시작 index.
            - count: `users`의 개수. 인자보다 적게 가져올 수도 있음.
            - users:  게시물 목록.
                - user_uid: 유저 고유 번호.
                - user_nickname: 유저의 별명.
                - user_profile: 유저 프로파일 사진 URL.
        """
        start = utils.get_request_argument('start', default=0, type=int)
        count = utils.get_request_argument('count', default=20, type=int)

        users = database.query_users(start, count)

        return jsonify(message='Success', start=start, count=len(users), users=users)

@api.route('/<uid>')
class UserAPI(Resource):
    def get(self, uid: str):
        """
        GET /api/users/<uid>

        지정된 유저 고유 번호로 유저의 정보를 가져옵니다.
        개인정보 보호를 위해 유저 고유 번호, 닉네임과 프로필사진 URL만 가져옵니다.

        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.

        returns:
            - message: 상태 메세지.
            - user_uid: 유저 고유 번호.
            - user_nickname: 유저의 별명.
            - user_profile: 유저 프로파일 사진 URL.
        """
        user = User.from_uid(uid)

        if user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        else:
            return jsonify(message='Success', user_uid=uid, user_nickname=user.nickname, user_profile=user.profile_url)


    @required_login
    def put(self, user: User, uid: str):
        """
        PUT /api/users/<uid>

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        본인 계정 또는 권한 요구: `admin.users.update`. 권한이 없는 경우 `403 - Forbidden` 반환.

        지정된 유저 고유 번호로 유저의 정보를 수정합니다.
        로그인한 유저와 지정된 유저 고유 번호가 일치할 경우 권한을 요구하지 않습니다.
        그 이외의 경우에는 상기한 권한이 요구됩니다.

        `user_nickname` 또는 `user_profile`의 인자를 요구합니다. 둘 다 정의되지 않은 경우 `400 - BadRequest` 반환됩니다.
        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.

        비밀번호 변경은 `/api/auth/<uid>/update_password` 에서 가능합니다.
        
        parameters:
            - [optional]user_nickname: 유저의 별명.
            - [optional]user_profile: 유저 프로파일 사진 URL. 서버에 등록된 URL이어야 함.

        returns:
            - message: 상태 메세지.
            - user_uid: 유저 고유 번호.
            - user_nickname: 유저의 별명.
            - user_profile: 유저 프로파일 사진 URL.
        """
        from . import resources_api

        target_user = User.from_uid(uid)

        if target_user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        elif target_user.id != user.id and not user.has_permission('admin.users.update'):
            raise Forbidden('Operation not permitted.')
    
        nickname = utils.get_post_argument('user_nickname', default=None)
        profile_url = utils.get_post_argument('user_profile', default=None)

        if nickname is not None:
            target_user.nickname = nickname
        
        if profile_url is not None:
            if not resources_api.is_valid_url(profile_url):
                raise BadRequest('Invalid profile_url.')
            else:
                target_user.profile_url = profile_url
        
        return jsonify(message='Success', user_uid=uid, user_nickname=target_user.nickname, user_profile=target_user.profile_url)
    

    @required_login
    def delete(self, user: User, uid: str):
        """
        DELETE /api/users/<uid>

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        본인 계정 또는 권한 요구: `admin.users.delete`. 권한이 없는 경우 `403 - Forbidden` 반환.

        지정된 유저 고유 번호로 유저를 삭제합니다.
        로그인한 유저와 지정된 유저 고유 번호가 일치할 경우 권한을 요구하지 않습니다.
        그 이외의 경우에는 상기한 권한이 요구됩니다.

        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.
        
        returns:
            - message: 상태 메세지.
        """
        target_user = User.from_uid(uid)

        if target_user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        elif target_user.id != user.id and not user.has_permission('admin.users.delete'):
            raise Forbidden('Operation not permitted.')
        else:
            target_user.delete()
            return jsonify(message='Success')


@api.route('/<uid>/permissions')
class PermissionsAPI(Resource):
    @required_login('admin.users.permissions')
    def get(self, user, uid):
        """
        GET /api/users/<uid>/permissions

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `admin.users.permissions`. 권한이 없는 경우 `403 - Forbidden` 반환.

        지정된 유저 고유 번호로 유저의 권한 정보를 가져옵니다.

        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.
        정상적으로 검색된 경우 `permissions`키로 값을 읽을 수 있습니다.

        returns:
            - message: 상태 메세지.
            - permissions: 권한 목록.
        """
        target_user = User.from_uid(uid)

        if target_user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        else:
            return jsonify(message='Success', permissions=target_user.permissions)


    @required_login('admin.users.permissions.grant')
    def put(self, user, uid):
        """
        PUT /api/users/<uid>/permissions

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `admin.users.permissions.grant`. 권한이 없는 경우 `403 - Forbidden` 반환.

        지정된 유저 고유 번호로 유저의 권한을 추가합니다.

        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.
        정의되지 않은 권한인 경우 `400 - BadRequest`가 반환됩니다.

        parameters:
            - permission: 유저에게 부여할 권한.

        returns:
            - message: 상태 메세지.
        """
        target_user = User.from_uid(uid)
        perm = utils.get_post_argument('permission')

        if target_user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        else:
            try:
                target_user.grant_permission(perm)
            except InvalidPermission:
                raise BadRequest('Invalid permission key %s.' % perm)
            else:
                return jsonify(message='Success')
    

    @required_login('admin.users.permissions.revoke')
    def delete(self, user, uid):
        """
        DELETE /api/users/<uid>/permissions

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `admin.users.permissions.revoke`. 권한이 없는 경우 `403 - Forbidden` 반환.

        지정된 유저 고유 번호로 유저의 권한을 삭제합니다.

        없는 유저 고유 번호인 경우 `404 - NotFound`가 반환됩니다.
        정의되지 않은 권한인 경우 `400 - BadRequest`가 반환됩니다.

        parameters:
            - permission: 유저에게 삭제할 권한.
        
        returns:
            - message: 상태 메세지.
        """
        target_user = User.from_uid(uid)
        perm = utils.get_request_argument('permission')

        if target_user is None:
            raise NotFound('UID {0} is not exist.'.format(uid))
        else:
            try:
                target_user.revoke_permission(perm)
            except InvalidPermission:
                raise BadRequest('Invalid permission key %s.' % perm)
            else:
                return jsonify(message='Success')
