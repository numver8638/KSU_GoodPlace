import pymysql
from os.path import dirname, exists, join
import os
import re
from Crypto.Random import random
from Crypto.Hash import SHA256
import base64
from werkzeug.security import generate_password_hash, gen_salt
import getpass
import json

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
    return ":".join(perms)


def main():
    current_dir = dirname(__file__)
    config_file = join(current_dir, 'config.json')

    if exists(config_file):
        confirm = input("config.json is already exists. override it? (default: no) ")

        if not re.match(r't(rue)?|y(es)?', confirm, re.IGNORECASE):
            print("user canceled operation. stop.")
            return
        else:
            print("override exist config.json.")
            os.remove(config_file)

    # application key
    client_id = input("type your Naver Map API application id: ")

    # Generate Secret keys
    encrypt_secret_key: str
    token_secret_key: str

    while True:
        encrypt_secret_key = input("type secret key for encryption. (default: auto-generate) ")

        if len(encrypt_secret_key) == 0:
            # auto generate key
            print("auto-generate secret key.")
            encrypt_secret_key = base64.b64encode(os.urandom(16)).decode('utf-8')
            break
        elif len(encrypt_secret_key) == 16:
            break
        else:
            print("length of secret key must be 16 due to AES limitation. please type again.")

    while True:
        token_secret_key = input("type secret key for token authentication. (default: auto-generate) ")
        
        if len(token_secret_key) == 0:
            # auto generate key
            print("auto-generate secret key.")
            token_secret_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            break
        elif len(token_secret_key) < 20:
            confirm = input("length of secret key suggests longer than 20. Keep going? (default: no)")
            if not re.match(r't(rue)?|y(es)?', confirm, re.IGNORECASE):
                print("confirmed.")
                break
            else:
                print("please type again.")
        else:
            break

    # Database informations
    db_host: str
    db_port: int
    db_user: str
    db_password: str

    db_host = input("database host name: ")
    while True:
        db_port = input("database port (default: 3306): ")

        if len(db_port) == 0:
            db_port = 3306
            break

        try:
            db_port = int(db_port)

            if db_port < 0 or db_port > 65535:
                raise ValueError()

        except ValueError:
            print("port number is not valid. try again.")
        else:
            break
    
    db_user = input("database user name: ")
    db_password = getpass.getpass("database password: ")

    # Get admin information
    user_id = input("super user id: ")
    user_pw = getpass.getpass("super user password: ")
    user_name = input("super user name: ")
    user_nickname = input("super user nickname: ")

    print("All information accepted. Start initialize...")

    # Create database and tables
    db = pymysql.connect(
        host=db_host,
        port=db_port,
        user=db_user,
        passwd=db_password,
        charset='utf8'
    )

    gen_db_user = 'WebDBUser'
    gen_db_password = base64.b64encode(os.urandom(32)).decode('utf-8')

    with db.cursor() as cursor:
        # Generate database and tables
        cursor.execute("CREATE DATABASE IF NOT EXISTS KSU_GoodPlace;")
        cursor.execute("USE KSU_GoodPlace;")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS UserTable(
                UserID VARCHAR(64) NOT NULL UNIQUE,
                UserUID CHAR(12) NOT NULL UNIQUE,
                UserPw CHAR(128) NOT NULL,
                UserName VARCHAR(10) NOT NULL,
                UserNickname VARCHAR(32) NOT NULL,
                UserProfile VARCHAR(128) NULL,
                UserPermissions VARCHAR(1024) NULL,
                TokenID CHAR(32) NULL,

                PRIMARY KEY (UserID, UserUID)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS PostTable(
                PostID INTEGER NOT NULL UNIQUE AUTO_INCREMENT,
                UserUID CHAR(12) NOT NULL,
                PostName VARCHAR(64) NOT NULL,
                PostAddress VARCHAR(128) NOT NULL,
                PostLocationLat FLOAT(10,7) NOT NULL,
                PostLocationLng FLOAT(10,7) NOT NULL,
                PostImage VARCHAR(128) NULL,

                PRIMARY KEY(PostID)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS CommentTable(
                CommentID INTEGER NOT NULL UNQUE AUTO_INCREMENT,
                UserUID CHAR(12) NOT NULL,
                PostID INTEGER NOT NULL,
                Comment VARCHAR(1024) NOT NULL,

                PRIMARY KEY (CommentID),
                FOREIGN KEY (UserUID) REFERENCES UserTable(UserUID),
                FOREIGN KEY (PostID) REFERENCES PostTable(PostID)
            );
            """
        )

        # Create user
        cursor.execute("CREATE USER %s@%s IDENTIFIED BY %s;", (gen_db_user, db_host, gen_db_password))
        cursor.execute("GRANT ALL PRIVILEGES ON KSU_GoodPlace.* TO %s@%s;", (gen_db_user, db_host))

        # Insert super user
        hashpw = generate_password_hash(SHA256.new(user_pw.encode('utf-8')).hexdigest(), method='pbkdf2:sha256:10000', salt_length=16)
        perms = serialize_permissions(PREDEFINED_PERMISSIONS)
        uid = gen_salt(12)

        cursor.execute("INSERT INTO UserTable VALUES(%s,%s,%s,%s,%s,NULL,%s);", (user_id, uid, hashpw, user_name, user_nickname, perms))
    
    db.commit()
    db.close()

    with open(config_file, 'w') as f:
        output = json.dumps(
            {
                'CLIENT_ID': client_id,
                'ENCRYPT_SECRET_KEY': encrypt_secret_key,
                'TOKEN_SECRET_KEY': token_secret_key,
                'DATABASE_HOST': db_host,
                'DATABASE_PORT': db_port,
                'DATABASE_USER': gen_db_user,
                'DATABASE_PW': gen_db_password
            }, indent=4
        )

        f.write(output)

    print("done.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)