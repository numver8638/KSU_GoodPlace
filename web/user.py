#
# auth.py
# - 유저 인증 관련 코드.
#
import base64
import functools

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import BLAKE2s
from Crypto.Util.Padding import pad, unpad
from flask import redirect, url_for, request, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Unauthorized, Forbidden
import jwt

from . import database

# 사전 정의된 권한 목록
# 이 목록을 기반으로 권한체계가 작동됩니다.
PREDEFINED_PERMISSIONS = [
    'user',
    'user.posts',
    'user.posts.upload',
    'user.posts.update',
    'user.posts.delete',
    'user.posts.comments',
    'user.posts.comments.update',
    'user.posts.comments.delete',
    'admin',
    'admin.users',
    'admin.users.update',
    'admin.users.delete',
    'admin.users.permissions',
    'admin.users.permissions.grant',
    'admin.users.permissions.revoke',
    'admin.posts',
    'admin.posts.update',
    'admin.posts.delete',
    'admin.posts.comments',
    'admin.posts.comments.update',
    'admin.posts.comments.delete',
    'admin.auth',
    'admin.auth.update_password'
]


def serialize_permissions(perms):
    """
    권한 목록을 문자열화.
    """
    return ":".join(perms)


def deserialize_permissions(string: str):
    """
    문자열화 된 권한목록을 다시 목록으로 변환.
    """
    return string.split(":")


def _generate_cipher():
    """
    암호화 객체를 생성.
    """
    secret = current_app.config['ENCRYPT_SECRET_KEY']
    # Generate initial vector from hash of ENCRYPT_SECRET_KEY.
    iv = BLAKE2s.new(digest_bits=128).update(secret).digest()
    
    return AES.new(secret, AES.MODE_CBC, iv)


def _verify_permission(perm: str):
    """
    `PREDEFINED_PERMISSIONS`에 정의된 권한인지 판단.
    정의되지 않은 권한이거나 유효하지 않은 권한 문자열이 입력된 경우 `InvalidPermission` 예외 발생.
    """
    if perm is None or len(perm) == 0:
        raise InvalidPermission('Permission cannot be None.')

    if perm not in PREDEFINED_PERMISSIONS:
        raise InvalidPermission('Unknown permission %s.' % perm)


class AuthException(Exception):
    """
    인증 실패시 발생하는 모든 예외의 베이스 클래스.
    """
    pass


class InvalidCredential(AuthException):
    """
    올바르지 않은 비밀번호이거나 유효하지 않은 인증 토큰으로
    인증을 시도할 경우 발생하는 예외.
    """
    pass


class InvalidPermission(AuthException):
    """
    정의되지 않은 권한일 경우 발생하는 예외.
    """
    pass


class UserIDConflict(AuthException):
    """
    유저의 아이디가 겹치는 경우 발생하는 예외.
    """
    pass


class User:
    """
    사용자(유저)를 나타내는 클래스.
    """

    def __sync_data(self):
        database.update_user(self.id, self.nickname, self.profile_url, self.__perms, self.__token_id)


    def __init__(self, id, uid, name, nickname, perms, profile_url, token_id):
        """
        `User` 클래스의 생성자. 직접 이용하지 말 것.
        필요시 `create_new_user()`, `from_id_pw()`, `from_token()`, `from_uid()` 정적 메서드를 이용할 것.
        """
        self.__id = id
        self.__uid = uid
        self.__name = name
        self.__nickname = nickname
        self.__perms = set(perms)
        self.__profile_url = profile_url
        self.__token_id = token_id


    @property
    def name(self):
        """
        유저의 이름. 실명인지 아닌지는 판단하지 않음.
        """
        return self.__name
    
    
    @property
    def id(self):
        """
        유저의 아이디. 실제 로그인에 이용됨.
        """
        return self.__id
    

    @property
    def uid(self):
        """
        유저 고유 번호. 보안에 민감한 아이디나 이름 대신 사용.
        """
        return self.__uid
    

    @property
    def nickname(self):
        """
        유저의 별명.
        """
        return self.__nickname

    
    @nickname.setter
    def nickname(self, value):
        self.__nickname = value

        self.__sync_data()
    

    @property
    def profile_url(self):
        """
        유저의 프로파일 이미지 주소.
        """
        return self.__profile_url
    

    @profile_url.setter
    def profile_url(self, value):
        from .api import resources_api
        
        if value is None or not resources_api.is_valid_url(value):
            value = url_for('static', filename='default_user.png')
        
        self.__profile_url = value

        self.__sync_data()


    @property
    def permissions(self):
        """
        유저의 권한 목록.
        """
        return list(self.__perms)

    
    @property
    def token_id(self):
        """
        현재 발급된 토큰의 고유 번호.
        """
        return self.__token_id
    

    @token_id.setter
    def token_id(self, value):
        self.__token_id = value

        self.__sync_data()


    def check_password(self, pw):
        """
        유저의 비밀번호가 맞는지 확인.
        맞을 경우 `True`, 다를 경우 `False` 반환.
        """
        return database.verify_credential(self.id, pw)


    def update_password(self, old_pw, new_pw):
        """
        유저의 비밀번호를 변경.

        전의 비밀번호가 일치해야 새로운 비밀번호로 변경되며
        전의 비밀번호가 일치하지 않는 경우에는 `InvalidCredential` 예외가 발생.
        """
        if not database.update_credential(self.id, old_pw, new_pw):
            raise InvalidCredential('Password mismatch.')


    def set_password(self, new_pw):
        """
        유저의 비밀번호를 설정.
        """
        database.set_credential(self.id, new_pw)


    def grant_permission(self, perm):
        """
        유저에게 권한을 부여. 상위의 권한을 부여한 경우 그 하위의 권한들도 전부 부여됨.
        """
        _verify_permission(perm)

        self.__perms.update([ p for p in PREDEFINED_PERMISSIONS if p.startswith(perm) ])
        
        self.__sync_data()
    

    def revoke_permission(self, perm):
        """
        유저에게 권한을 박탈. 상위의 권한을 박탈한 경우 그 하위의 권한들도 전부 박탈됨.
        """
        _verify_permission(perm)

        self.__perms.difference_update([ p for p in self.__perms if p.startswith(perm) ])

        self.__sync_data()
    

    def has_permission(self, permission):
        """
        유저가 권한이 있는지 판단.
        """
        allowed = permission in self.__perms

        index = permission.find('.')
        while index > 0:
            allowed &= permission[:index] in self.__perms
            index = permission.find('.', index + 1)
        
        return allowed


    def is_annonymous(self):
        """
        이 유저가 익명 유저인지 판단. 여기서는 항상 `False`.
        """
        return False


    def delete(self):
        """
        유저를 삭제.
        """
        database.delete_user(self.id)


    @staticmethod
    def __get_token():
        """
            Get token from Authorized header or cookies.
            Returns `None` if cannot find token in header nor cookie.
        """
        token: str

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

            return token[7:] if token.startswith('Bearer ') else None
        elif '__USER_TOKEN' in request.cookies:
            token = request.cookies['__USER_TOKEN']
            return token
        else:
            return None
    

    def to_token(self):
        """
        `User` 객체로 부터 인증 토큰을 생성.
        """
        assert self.token_id is not None

        payload = {
            'user_uid': self.uid,
            'token_id': self.token_id
        }

        token = jwt.encode(payload, current_app.config['TOKEN_SECRET_KEY'])

        cipher = _generate_cipher()
        encrypted_token = cipher.encrypt(pad(token, AES.block_size))

        return base64.b64encode(encrypted_token).decode('utf-8')


    @staticmethod
    def create_new_user(id, pw, name, nickname, profile, is_admin=False):
        """
        새로운 `User` 객체를 생성하고 데이터베이스에 등록.

        이미 있는 유저인 경우 `UserIDConflict` 예외가 발생.
        """
        if database.is_used_id(id):
            raise UserIDConflict("User ID '%s' is already in use." % id)

        if profile is None or not resources_api.is_valid_url(profile):
            profile = url_for('static', filename='images/default_user.svg')

        perms: set
        if is_admin:
            perms = set(PREDEFINED_PERMISSIONS)
        else:
            perms = set(filter(lambda p: p.startswith('user'), PREDEFINED_PERMISSIONS))

        database.create_user(id, pw, name, nickname, profile, perms)


    @staticmethod
    def from_id_pw(id, pw):
        """
        아이디, 비밀번호로 `User` 객체를 생성.

        유저가 없거나 아이디와 비밀번호가 일치하지 않는 경우 `InvalidCredential` 예외가 발생함.
        """
        user_data = database.query_user(id, pw)

        if user_data is None:
            raise InvalidCredential()
        else:
            # generate random id for token.
            rand = Random.new().read(16)
            token_id = "".join([ "{0:02x}".format(b) for b in rand ])

            user = User(id, user_data['uid'], user_data['name'], user_data['nickname'], user_data['perms'], user_data['profile_url'], token_id)

            user.__sync_data()

            return user


    @staticmethod
    def from_token(token:str):
        """
        인증 토큰으로부터 `User` 객체를 생성.
        """
        try:
            cipher = _generate_cipher()

            decrypted_token = unpad(cipher.decrypt(base64.b64decode(token.encode('utf-8'))), AES.block_size).decode('utf-8')
            data = jwt.decode(decrypted_token, current_app.config['TOKEN_SECRET_KEY'])

            user = User.from_uid(data['user_uid'])

            return user if user.token_id == data['token_id'] else AnnonymousUser()
        except (ValueError, KeyError):
            return AnnonymousUser()


    @staticmethod
    def from_uid(uid:int):
        """
        유저 고유 번호로 `User` 객체를 생성.
        """
        user_data = database.query_user_by_uid(uid)

        if user_data is None:
            return AnnonymousUser()
        else:
            return User(user_data['id'], uid, user_data['name'], user_data['nickname'], user_data['perms'], user_data['profile_url'], user_data['token_id'])


    @staticmethod
    def get_current_user():
        """
        현재 로그인 되어 있는 유저를 가져옴. 로그인 되어있지 않다면 `AnnonymousUser` 객체가 반환.
        """
        token = User.__get_token()

        if token is None:
            return AnnonymousUser()
        else:
            return User.from_token(token)


class AnnonymousUser(User):
    """
    로그인 하지 않은 익명 유저를 나타내는 클래스.

    자세한 사항은 `User` 클래스 참조.
    """
    def __init__(self):
        super().__init__(None,'ANNO_USER',None,None,[],None,None)


    @property
    def name(self):
        return 'Annonymous'
    
    
    @property
    def id(self):
        return '<annonymous>'
    

    @property
    def uid(self):
        return 'ANNO_USER'


    @property
    def nickname(self):
        return 'Annonymous'

    @nickname.setter
    def nickname(self, value):
        raise NotImplementedError('Cannot change nickname of AnnonymousUser.')

    
    @property
    def token_id(self):
        return '<NEVER_VALID>'
    

    @token_id.setter
    def token_id(self, value):
        raise NotImplementedError('Cannot set token id of AnnonymousUser.')


    def check_password(self, pw):
        raise NotImplementedError('Cannot check password of AnnonymousUser.')


    def update_password(self, old_pw, new_pw):
        raise NotImplementedError('Cannot change password of AnnonymousUser.')


    def set_password(self, new_pw):
        raise NotImplementedError('Cannot set password of AnnonymousUser.')
    

    def grant_permission(self, perm):
        raise NotImplementedError('Cannot grant permission of AnnonymousUser.')
    

    def revoke_permission(self, perm):
        raise NotImplementedError('Cannot revoke permission of AnnonymousUser.')


    def has_permission(self, permission):
        # Always false when user is annonymous.
        return False


    def is_annonymous(self):
        return True
    
    
    def delete(self):
        raise NotImplementedError('Cannot delete AnnonymousUser.')

    
    def to_token(self):
        raise NotImplementedError('Cannot get token of AnnonymousUser.')


def check_user_id_conflict(id):
    """
    아이디 중복 유무를 확인.
    `True`이면 중복, 아닐시 `False`.
    """
    return database.is_used_id(id)


def required_login(required_perm=None):
    """
    로그인이 필요한 HTTP method에 적용되는 decorator.
    이 decorator가 있는 함수에는 로그인 유무가 확인되어
    로그인이 되어 있는 경우에만 함수가 실행됨.

    `required_perm` 이 지정된경우 그 권한이 있는 유저일 경우에만 실행됨.

    로그인 되어있지 않은경우 `werkzeug.exceptions.Unauthorized` 예외가,
    권한이 없는 경우 `werkzeug.exceptions.Forbidden` 예외가 발생함.
    """

    perm = required_perm if isinstance(required_perm, str) else None

    def wrapper(fn):
        @functools.wraps(fn)
        def decorator(*args, **kwargs):
            user = User.get_current_user()

            if user.is_annonymous():
                raise Unauthorized('Requested operation is authorized operation.')
            elif perm is not None and not user.has_permission(perm):
                raise Forbidden('Operation not permitted.')
            else:
                ka = dict(kwargs)
                ka['user'] = user

                return fn(*args, **ka)
        
        return decorator
    
    return wrapper if isinstance(required_perm, str) else wrapper(required_perm)