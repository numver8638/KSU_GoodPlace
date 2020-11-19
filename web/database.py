import pymysql
from flask import current_app, g
from werkzeug.security import check_password_hash, generate_password_hash, gen_salt
import contextlib
from . import user

def get_db():
    """
    데이터 베이스 객체를 가져 옴.
    컨텍스트 내에서 필요시 생성하고 컨텍스트가 끝나기 전까지 계속 연결이 유지됨.
    """
    db = getattr(g, '_database', None)

    if db is None:
        db = g._database = pymysql.connect(
            host=current_app.config['DATABASE_HOST'],
            user=current_app.config['DATABASE_USER'],
            password=current_app.config['DATABASE_PW'],
            port=current_app.config['DATABASE_PORT'],
            db='KSU_GoodPlace',
            charset='utf8'
        )

    return db


@contextlib.contextmanager
def get_cursor():
    """
    데이터 베이스 `Cursor` 객체를 가져옴.

    `with` 문과 같이 사용함.
    """
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)

    try:
        yield cursor
    finally:
        db.commit()
        cursor.close()


#
# Queries for auth.py
#
def is_used_id(id):
    """
    사용중인 아이디를 확인하는 쿼리.
    `True`이면 사용 중, `False`면 사용 가능.
    """
    QUERY = "SELECT COUNT(*) FROM UserTable WHERE UserID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, id)

        count = cursor.fetchone()['COUNT(*)']

        return count != 0


def create_user(id, pw, name, nickname, profile_url, perms):
    """
    새로운 사용자를 생성하는 쿼리.
    """
    QUERY = "INSERT INTO UserTable VALUES (%s,%s,%s,%s,%s,%s,%s);"

    pwhash = generate_password_hash(pw, method='pbkdf2:sha256:10000', salt_length=16)
    uid = gen_salt(12)

    serialzed_perms = user.serialize_permissions(perms)

    with get_cursor() as cursor:
        cursor.execute(QUERY, (id, uid, pwhash, name, nickname, profile_url, serialzed_perms))


def update_user(id, name, nickname, profile_url, perms):
    QUERY = "UPDATE UserTable SET UserName=%s, UserNickname=%s, UserProfile=%s, UserPermissions=%s WHERE UserID=%s;"
    
    serialized_perms = user.serialize_permissions(perms)

    with get_cursor() as cursor:
        cursor.execute(QUERY, (name, nickname, profile_url, serialized_perms, id))


def verify_credential(id, pw):
    QUERY = "SELECT UserPw FROM UserTable WHERE UserID=%s;"

    pwhash: str

    with get_cursor() as cursor:
        cursor.execute(QUERY, id)

        result = cursor.fetchone()
        
        if result is None:
            hashpw = None
        else:
            hashpw = result['UserPw']
    
    return False if pwhash is None else check_password_hash(pwhash, pw)


def update_credential(id, old_pw, new_pw):
    QUERY = "UPDATE UserTable SET UserPw=%s WHERE UserID=%s;"

    if not verify_credential(id, old_pw):
        return False

    new_pwhash = generate_password_hash(new_pw, method='pbkdf2:sha256:10000', salt_length=16)

    with get_cursor() as cursor:
        cursor.execute(QUERY, (new_pwhash, id))

    return True

def query_user(id, pw):
    QUERY = "SELECT * FROM UserTable WHERE UserID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, id)

        result = cursor.fetchone()

        if result is None:
            return None
        elif check_password_hash(result['UserPw'], pw):
            return {
                'id': result['UserID'],
                'uid': result['UserUID'],
                'name': result['UserName'],
                'nickname': result['UserNickname'],
                'profile_url': result['UserProfile'],
                'perms': user.deserialize_permissions(result['UserPermissions'])
            }
        else:
            return None

def query_user_by_uid(uid):
    QUERY = "SELECT * FROM UserTable WHERE UserUID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, uid)

        result = cursor.fetchone()

        if result is None:
            return None
        else:
            return {
                'id': result['UserID'],
                'uid': result['UserUID'],
                'name': result['UserName'],
                'nickname': result['UserNickname'],
                'profile_url': result['UserProfile'],
                'perms': user.deserialize_permissions(result['UserPermissions'])
            }


def delete_user(id):
    QUERY = "DELETE FROM UserTable WHERE UserID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, id)


def query_users(start, count):
    QUERY = "SELECT UserUID, UserNickname, UserProfile FROM UserTable LIMIT %s,%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (start, count))

        result = cursor.fetchall()

        return [ { 'uid': data['UserUID'], 'nickname': data['UserNickname'], 'profile_url': data['UserProfile'] } for data in result ]

#
# Queries for posts
#
def create_comment(post_id, user_uid, comment):
    QUERY = "INSERT INTO CommentTable(UserUID,PostID,Comment) VALUES (%s,%s,%s);"
    
    with get_cursor() as cursor:
        cursor.execute(QUERY, (user_uid, post_id, comment))


def update_comment(comment_id, comment):
    QUERY = "UPDATE CommentTable SET Comment=%s WHERE CommentID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (comment, comment_id))


def delete_comment(comment_id):
    QUERY = "DELETE FROM CommentTable WHERE CommentID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, comment_id)


def get_comments(post_id, start, count):
    QUERY = "SELECT U.UserUID, U.UserNickname, U.UserProfile, C.CommentID, C.Comment FROM CommentTable as C JOIN UserTable as U WHERE C.PostID=%s LIMIT %s,%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (post_id, start, count))

        return [ {
            'user_uid': result['UserUID'],
            'user_nickname': result['UserNickname'],
            'user_profile': result['UserProfile'],
            'comment_id': result['CommentID'],
            'comment': result['Comment']
        } for result in cursor.fetchall() ]


def get_comment(comment_id):
    QUERY = "SELECT U.UserUID, U.UserNickname, U.UserProfile, C.CommentID, C.Comment FROM CommentTable as C JOIN UserTable as U WHERE CommentID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, comment_id)

        result = cursor.fetchone()

        if result is None:
            return None
        else:
            return {
                'user_uid': result['UserUID'],
                'user_nickname': result['UserNickname'],
                'user_profile': result['UserProfile'],
                'comment_id': result['CommentID'],
                'comment': result['Comment']
            }


def create_post(user_uid, name, addr, loc, picture_url):
    QUERY = "INSERT INTO PostTable(UserUID, PostName, PostAddress, PostLocationLat, PostLocationLng, PostImage) VALUES (%s,%s,%s,%s,%s,%s);"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (user_uid, name, addr, loc.lat, loc.lng, picture_url))


def update_post(post_id, name, addr, loc, picture_url):
    QUERY = "UPDATE PostTable SET PostName=%s, PostAddress=%s, PostLocationLat=%s, PostLocationLng=%s, PostImage=%s WHERE PostID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (name, addr, loc.lat, loc.lng, picture_url, post_id))


def delete_post(post_id):
    QUERY = "DELETE FROM PostTable WHERE PostID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, post_id)


def get_post(post_id):
    QUERY = "SELECT * FROM PostTable WHERE PostID=%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, post_id)

        result = cursor.fetchone()

        if result is None:
            return None
        else:
            return {
                'user_uid': result['UserUID'],
                'post_id': result['PostID'],
                'post_name': result['PostName'],
                'post_address': result['PostAddress'],
                'post_lat': result['PostLocationLat'],
                'post_lng': result['PostLocationLng'],
                'post_image_url': result['PostImage']
            }


def get_posts(start, count):
    QUERY = "SELECT * FROM PostTable LIMIT %s,%s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (start, count))

        return [ {
            'user_uid': result['UserUID'],
            'post_id': result['PostID'],
            'post_name': result['PostName'],
            'post_address': result['PostAddress'],
            'post_lat': result['PostLocationLat'],
            'post_lng': result['PostLocationLng'],
            'post_image_url': result['PostImage']
        } for result in cursor.fetchall() ]


def find_posts_by_name(name):
    QUERY = "SELECT * FROM PostTable WHERE PostName LIKE %s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, "%" + name + "%")

        return [ {
            'user_uid': result['UserUID'],
            'post_id': result['PostID'],
            'post_name': result['PostName'],
            'post_address': result['PostAddress'],
            'post_lat': result['PostLocationLat'],
            'post_lng': result['PostLocationLng'],
            'post_image_url': result['PostImage']
        } for result in cursor.fetchall() ]


def find_posts_by_location(begin, end):
    QUERY = "SELECT * FROM PostTable WHERE PostLocationLat BETWEEN %s AND %s AND PostLocationLng BETWEEN %s and %s;"

    with get_cursor() as cursor:
        cursor.execute(QUERY, (begin.lat, end.lat, begin.lng, end.lng))

        return [ {
            'user_uid': result['UserUID'],
            'post_id': result['PostID'],
            'post_name': result['PostName'],
            'post_address': result['PostAddress'],
            'post_lat': result['PostLocationLat'],
            'post_lng': result['PostLocationLng'],
            'post_image_url': result['PostImage']
        } for result in cursor.fetchall() ]
