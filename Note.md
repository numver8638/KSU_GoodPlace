# Note
개발시 중점사항이나 참고사항들을 작성한 노트입니다.
다른 인원들도 볼 수 있게 도움되겠다 싶은 사항들을 꼭 적어주세요.

# Naver Maps API
Google Maps API는 사용료가 있어서 무료인 Naver Maps API를 사용하기로 했습니다.

> 주의사항: Naver Maps API를 이용할 때 꼭 지켜야 하는 규약이 있으니 [여기](https://docs.ncloud.com/ko/naveropenapi_v3/maps/overview.html)를 참고하여 코딩시 준수해주시기 바랍니다.
> Application ID는 본인 것을 발급받아 테스트 하시거나 신진환에게 문의주시면 Application ID를 알려드리겠습니다.

## Web Dynamic Map
예제: [Naver Maps Javascript API](https://navermaps.github.io/maps.js.ncp/docs/tutorial-digest.example.html)

# PyMySQL
Flask framework 안에 데이터베이스 관련 api가 없는 관계로 MySQL과 연동할 다른 라이브러리를 사용합니다.

> TODO: 꼭 MySQL을 써야 되는지. 일단은 배운것이 MySQL이라 사용하지만 가볍게 써도 된다면 sqlite3도 괜찮은 대안으로 보임. 파이썬 기본 내장 라이브러리 이기도 하고.

도움이 될 만한 예제 사이트들:
- [Python으로 MySQL 사용하기](https://yurimkoo.github.io/python/2019/09/14/connect-db-with-python.html)
- [예제로 배우는 파이썬 프로그래밍](http://pythonstudy.xyz/python/article/202-MySQL-%EC%BF%BC%EB%A6%AC)
- [데이터베이스 기본 - pymysql 모듈 이해 및 실습](https://www.fun-coding.org/mysql_basic6.html)
