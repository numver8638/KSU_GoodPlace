# KSU_GoodPlace
데이터베이스 프로젝트 - 군산대 통합장소시스템

> 꼭 Note.md 읽어주세요.

# 실행방법
먼저 다운로드/클론을 받은 후에 초기화 스크립트 `initialize.py`를 먼저 실행해주세요.
네이버 지도 Application ID, 데이터베이스 설정 및 초기 관리자 계정 설정을 진행합니다.
설정이 완료되었다면 `config.json` 파일이 생성됩니다.

## On Windows
```
> pip install flask flask-restx pymysql pycryptodome pyjwt
> set FLASK_APP=web
> set FLASK_ENV=development
> flask run
```

## On macOS / Linux
```
> pip install flask flask-restx pymysql pycryptodome pyjwt
> FLASK_APP=web FLASK_ENV=development flask run
```

# Requisites
- Python >= 3.7
- Flask
- Flask-RestX
- PyMySQL
- pycryptodome
- PyJWT