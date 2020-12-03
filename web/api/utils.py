#
# utils.py
# - 유틸리티 함수들이 정의된 모듈.
#
from base64 import b64decode, b64encode
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import BLAKE2s, SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from flask import request
from werkzeug.exceptions import BadRequest
import json
import time


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


class InvalidToken(Exception):
    """
    유효하지 않은 토큰일 경우 발생하는 예외.
    """
    pass


class CorruptedData(Exception):
    """
    데이터가 변형되었거나 토큰과 데이터가 일치하지 않는 경우 발생하는 예외.
    """
    pass



def _generate_cipher(secret: str):
    # Generate initial vector from hash of ENCRYPT_SECRET_KEY.
    iv = BLAKE2s.new(digest_bits=128).update(secret).digest()
    
    return AES.new(secret, AES.MODE_CBC, iv)


def generate_token(request_id:str, secret: str):
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

    public_key = b64encode(pubkey).decode('utf-8')
    private_key = b64encode(prikey)
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

    cipher = _generate_cipher(secret)
    data = pad(json.dumps(token).encode('utf-8'), AES.block_size)
    encrypted_token = cipher.encrypt(data)

    return { 'key': public_key, 'token': b64encode(encrypted_token).decode('utf-8') }


def _get_token_data(token_: str, secret: str):
    """
    발급한 토큰에서 다시 데이터를 복호화/검증 하는 함수.

    토큰의 해쉬값이 올바른지, 발급시간으로부터 30초 이내인지 등을 확인.
    """
    try:
        encrypted_token = b64decode(token_.encode('utf-8'))

        cipher = _generate_cipher(secret)
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
            raise InvalidToken('Token is expired.')

        return token
    except (KeyError, ValueError) as e:
        raise InvalidToken('Invalid token.')


def verify_and_get_data(encrypted_data, encrypted_token, secret) -> dict:
    """
    유저가 보낸 데이터를 복호화하고 적절한 요청인지 확인하는 함수.

    적절한 요청인 경우 복호화된 데이터가 반환되고 유효하지 않을 시 `werkzeug.exceptions.BadRequest` 예외가 발생.
    """
    token = _get_token_data(encrypted_token, secret)

    try:
        key = b64decode(token['private_key'].encode('utf-8'))

        rsa = RSA.import_key(key)
        cipher = PKCS1_v1_5.new(rsa)
        sentinel = Random.new().read(16)
        data = cipher.decrypt(b64decode(encrypted_data.encode('utf-8')), sentinel)
        
        if data == sentinel:
            raise ValueError()
        else:
            data = data.decode('utf-8')

        json_data = json.loads(data)

        if json_data['request_id'] != token['request_id']:
            raise CorruptedData('request - token mismatch.')
        
        return json_data
    except (KeyError, ValueError, UnicodeError) as e:
        raise CorruptedData('Data corrupted.')