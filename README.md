# KSU_GoodPlace
데이터베이스 프로젝트 - 군산대 통합장소시스템

> 꼭 Note.md 읽어주세요.

# 실행방법
먼저 다운로드/클론을 받은 후에 루트 폴더에 `config.json` 파일을 만든 후 내용을 아래와 같이 넣어주세요.
예시:
``` json
{
    "CLIENT_ID": "<your_client_id>"
}
```
> `<your_client_id>` 부분은 본인의 Naver Map API Application ID를 넣으시거나 따로 문의 주세요.

## On Windows
```
> pip install flask pymysql
> set FLASK_APP=web
> set FLASK_ENV=development
> flask run
```

## On macOS / Linux
```
> pip install flask pymysql
> FLASK_APP=web FLASK_ENV=development flask run
```

# Requisites
- Python >= 3.7
- Flask
- PyMySQL
