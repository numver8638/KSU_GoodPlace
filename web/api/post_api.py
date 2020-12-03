from flask import escape, Markup
from flask_restx import Namespace, Resource
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from . import utils
from ..user import User, required_login
from ..post import Post, Location


api = Namespace('/posts')


@api.route('')
class PostsAPI(Resource):
    def get(self):
        """
        GET /api/posts

        작성된 게시물 목록을 반환.

        parameters:
            - [optional]count: 게시물을 가져올 최대 개수. 기본값: 20
            - [optional]start: 시작 index. 기본값: 0

        returns:
            - message: 상태 메세지.
            - start: 시작 index.
            - count: `posts`의 개수. 인자보다 적게 가져올 수도 있음.
            - posts:  게시물 목록.
                - id: 게시물 고유 번호.
                - name: 게시물 이름.
                - address: 게시물의 주소.
                - location: 게시물의 지리적 좌표.
                - picture_url: 게시물 사진.
        """
        start = utils.get_request_argument('start', default=0, type=int)
        count = utils.get_request_argument('count', default=20, type=int)

        posts = Post.get_posts(start, count)

        return {
            'message': 'Success',
            'start': start,
            'count': len(posts),
            'posts': [ {
                'id': post.id,
                'name': post.name,
                'address': post.address,
                'location': {
                    "latitude": post.location.lat,
                    "longitude": post.location.lng
                },
                'picture_url': post.picture_url,
                'category': post.category
            } for post in posts ]
        }


    @required_login('user.posts.upload')
    def post(self, user):
        """
        POST /api/posts

        게시물 업로드.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `user.posts.upload`. 권한이 없는 경우 `403 - Forbidden` 반환.
        
        parameters:
            - name: 게시물 이름.
            - address: 게시물 주소.
            - location: 게시물 지리적 주소.
            - image_url: 게시물 사진 URL.
            - content:
            - category:
            
        returns:
            - message: 상태 메세지.
            - id: 게시물 고유 번호.
        """
        from . import resources_api

        name = utils.get_post_argument('name', is_required=True)
        addr = utils.get_post_argument('address', is_required=True)
        location_str: str = utils.get_post_argument('location', is_required=True)
        category = utils.get_post_argument('category', is_required=True)
        image_url = utils.get_post_argument('image_url')
        raw_content = utils.get_post_argument('content')

        # Replace new-lines to <br> tags.
        content = str(escape(raw_content).replace('\n', Markup('<br>')))

        if image_url is not None and not resources_api.is_valid_url(image_url):
            raise BadRequest('Invalid image url.')

        loc = location_str.split(',')
        if len(loc) != 2:
            raise BadRequest('Invalid location format.')

        location: Location
        try:
            location = Location(loc[0], loc[1])
        except TypeError:
            raise BadRequest('Invalid location type.')

        Post.create_post(user, name, addr, location, image_url, content, category)

        return { 'message': 'Success' }


@api.route('/search')
class SearchAPI(Resource):
    def get(self):
        """
        GET /api/posts/search

        게시물을 검색.
        `query`로 이름 기반 검색을 하거나 `coord`로 지리적 범위 기반 검색이 가능.

        `query`와 `coord`가 동시에 정의되지 않거나 둘 다 정의된 경우 `400 - BadRequest`반환.

        parameters:
            - query: 게시물을 가져올 최대 개수. 기본값: 20
            - coord: 시작 index. 기본값: 0

        returns:
            - message: 상태 메세지.
            - count: `posts`의 개수.
            - posts:  게시물 목록.
                - id: 게시물 고유 번호.
                - name: 게시물 이름.
                - address: 게시물의 주소.
                - location: 게시물의 지리적 좌표.
                - picture_url: 게시물 사진.
        """
        query = utils.get_request_argument('query')
        coord = utils.get_request_argument('coord')

        results = []

        if query is not None and coord is not None:
            raise BadRequest("Cannot be sent 'query' and 'coord' at same time.")
        elif query is None and coord is None:
            raise BadRequest("Omitted required data 'query' or 'coord'.")
        elif query is not None:
            # Query
            if len(query) > 1 and query.startswith('#'):            
                results = Post.query_by_category(query[1:])
            else:
                results = Post.query_by_name(query)
        else:
            # Coord
            coords = coord.split(',')

            if len(coords) != 4:
                raise BadRequest('Invalid coord format.')

            begin: Location
            end: Location
            
            try:
                begin = Location(coords[0], coords[1])
                end = Location(coords[2], coords[3])

                if begin > end:
                    raise BadRequest('Begin position is grater than end point.')
            except TypeError:
                raise BadRequest('Invalid coord format.')

            results = Post.query_by_location(begin, end)

        return { 
            'message': 'Success',
            'count': len(results),
            'posts': [ {
                'id': post.id,
                'name': post.name,
                'address': post.address,
                'location': {
                    "latitude": post.location.lat,
                    "longitude": post.location.lng
                },
                'picture_url': post.picture_url,
                'category': post.category
            } for post in results ]
        }


@api.route('/recommends')
class GetRecommendsAPI(Resource):
    def get(self):
        start = utils.get_request_argument('start', default=0, type=int)
        count = utils.get_request_argument('count', default=20, type=int)

        posts = Post.get_posts_by_recommends(start, count)

        return {
            'message': 'Success',
            'start': start,
            'count': len(posts),
            'posts': [ {
                'id': post.id,
                'name': post.name,
                'address': post.address,
                'location': {
                    "latitude": post.location.lat,
                    "longitude": post.location.lng
                },
                'picture_url': post.picture_url,
                'category': post.category
            } for post in posts ]
        }


@api.route('/<int:post_id>')
class PostAPI(Resource):
    def get(self, post_id):
        """
        GET /api/posts/<post_id>

        지정된 게시물 번호로 게시물 정보를 가져옵니다.

        없는 게시물 번호인경우 `404 - NotFound`가 반환됩니다.

        returns:
            - message: 상태 메세지.
            - id: 게시물 고유 번호.
            - name: 게시물 이름.
            - address: 게시물의 주소.
            - location: 게시물의 지리적 좌표.
            - picture_url: 게시물 사진.
        """
        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        user = User.get_current_user()

        return { 
            'message': 'Success',
            'id': post_id,
            'name': post.name,
            'address': post.address,
            'location': {
                "latitude": post.location.lat,
                "longitude": post.location.lng
            },
            'can_edit': (post.writer.uid == user.uid and user.has_permission('user.posts.update')) or user.has_permission('admin.posts.update'),
            'can_delete': (post.writer.uid == user.uid and user.has_permission('user.posts.delete')) or user.has_permission('admin.posts.delete'),
            'picture_url': post.picture_url,
            'content': post.content,
            'recommend_count': post.get_recommend_count(),
            'category': post.category
        }
    

    @required_login('user.posts.update')
    def put(self, user, post_id):
        """
        PUT /api/posts/<post_id>

        지정된 게시물 번호의 게시물의 정보를 수정합니다.

        없는 게시물 번호인경우 `404 - NotFound`가 반환됩니다.

        권한 요구: `user.posts.update`. 권한이 없는 경우 `403 - Forbidden` 반환.
        작성자와 로그인한 유저가 다른경우 `admin.posts.update` 권한이 있을 경우에만 수정이 가능합니다.

        parameters:
            - name: 게시물 이름.
            - address: 게시물의 주소.
            - location: 게시물의 지리적 좌표.
            - picture_url: 게시물 사진.

        returns:
            - message: 상태 메세지.
        """
        from . import resources_api

        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        if post.writer.uid != user.uid and not user.has_permission('admin.posts.update'):
            raise BadRequest('Operation not permitted.')

        name = utils.get_post_argument('name')
        address = utils.get_post_argument('address')
        location_str = utils.get_post_argument('location')
        picture_url = utils.get_post_argument('picture_url')
        raw_content = utils.get_post_argument('content')
        category = utils.get_post_argument('category')

        if name is not None:
            post.name = name

        if address is not None:
            post.address = address

        if location_str is not None:
            loc = location_str.split(',')

            if len(loc) != 2:
                raise BadRequest('Invalid location format.')
            
            post.location = Location(loc[0], loc[1])
        
        if picture_url is not None:
            if not resources_api.is_valid_url(picture_url):
                raise BadRequest('Invalid picture_url')
            else:
                post.picture_url = picture_url

        if category is not None:
            post.category = category
        
        if raw_content is not None:        
            # Replace new-lines to <br> tags.
            post.content = str(escape(raw_content).replace('\n', Markup('<br>')))

        return { 'message': 'Success' }
    

    @required_login('user.posts.delete')
    def delete(self, user, post_id):
        """
        DELETE /api/posts/<post_id>

        지정된 게시물 번호로 게시물을 삭제합니다.

        없는 게시물 번호인경우 `404 - NotFound`가 반환됩니다.

        권한 요구: `user.posts.delete`. 권한이 없는 경우 `403 - Forbidden` 반환.
        작성자와 로그인한 유저가 다른경우 `admin.posts.delete` 권한이 있을 경우에만 삭제가 가능합니다.

        returns:
            - message: 상태 메세지.
        """
        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)


        if post.writer.uid != user.uid and not user.has_permission('admin.posts.update'):
            raise BadRequest('Operation not permitted.')
            
        post.delete()

        return { 'message': 'Success' }


@api.route('/<int:post_id>/recommends')
class RecommendsAPI(Resource):
    @required_login('user.posts')
    def get(self, user, post_id):
        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        return { 'message': 'Success', 'recommended': post.get_recommend(user.uid) }


    @required_login('user.posts')
    def post(self, user, post_id):
        post = Post.from_id(post_id)
        recommend = utils.get_post_argument('recommend', is_required=True, type=bool)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)


        post.set_recommend(user.uid, recommend)

        return { 'message': 'Success' }


@api.route('/<int:post_id>/comments')
class CommentPublicAPI(Resource):
    def get(self, post_id):        
        """
        GET /api/posts/<post_id>/comments

        지정된 게시물의 댓글의 목록을 반환.

        parameters:
            - [optional]count: 댓글을 가져올 최대 개수. 기본값: 20
            - [optional]start: 시작 index. 기본값: 0

        returns:
            - message: 상태 메세지.
            - start: 시작 index.
            - count: `comments`의 개수. 인자보다 적게 가져올 수도 있음.
            - comments:  댓글 목록.
                - post_id: 게시물 고유 번호.
                - user_uid: 유저 고유 번호.
                - user_nickname: 유저의 별명.
                - user_profile: 유저의 프로파일 사진 URL.
                - comment: 댓글 내용.
        """
        post = Post.from_id(post_id)
        start = utils.get_request_argument('start', default=0, type=int)
        count = utils.get_request_argument('count', default=20, type=int)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        comments = post.get_comments(start, count)
        user = User.get_current_user()

        return {
            'message': 'Success',
            'start': start,
            'count': len(comments),
            'comments': [ {
                'post_id': post.id,
                'user_id': c.writer.id,
                'user_uid': c.writer.uid,
                'user_nickname': c.writer.nickname,
                'user_profile': c.writer.profile_url,
                'can_edit': (c.writer.uid == user.uid and user.has_permission('user.posts.comments.update')) or user.has_permission('admin.posts.comments.update'),
                'can_delete': (c.writer.uid == user.uid and user.has_permission('user.posts.comments.delete')) or user.has_permission('admin.posts.comments.delete'),
                'comment_id': c.id,
                'comment': c.comment 
            } for c in comments ]
        }

    
    @required_login('user.posts.comments')
    def post(self, user, post_id):
        """
        POST /api/posts/<post_id>/comments

        지정된 게시물의 댓글을 작성함.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `user.posts.comments`. 권한이 없는 경우 `403 - Forbidden` 반환.

        parameters:
            - comment: 댓글 내용.

        returns:
            - message: 상태 메세지.
        """
        post = Post.from_id(post_id)
        msg = utils.get_post_argument('comment', is_required=True)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        comment = post.write_comment(user, msg)

        return { 'message': 'Success' }


@api.route('/<int:post_id>/comments/<int:comment_id>')
class CommentAuthorizedAPI(Resource):
    def get(self, post_id, comment_id):        
        """
        GET /api/posts/<post_id>/comments/<comment_id>

        지정된 게시물의 지정된 댓글을 반환.

        returns:
            - message: 상태 메세지.
            - post_id: 게시물 고유 번호.
            - user_uid: 유저 고유 번호.
            - user_nickname: 유저의 별명.
            - user_profile: 유저의 프로파일 사진 URL.
            - comment: 댓글 내용.
        """
        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        comment = post.find_comment_by_id(comment_id)

        if comment is None:
            raise NotFound('Comment ID %d is not found.' % comment_id)

        user = User.get_current_user()

        return {
            'message': 'Success',
            'post_id': post.id,
            'user_id': comment.writer.id,
            'user_uid': comment.writer.uid,
            'user_nickname': comment.writer.nickname,
            'user_profile': comment.writer.profile_url,
            'can_edit': (post.writer.uid == user.uid and user.has_permission('user.posts.comment.update')) or user.has_permission('admin.posts.comment.update'),
            'can_delete': (post.writer.uid == user.uid and user.has_permission('user.posts.comment.delete')) or user.has_permission('admin.posts.comments.delete'),
            'comment_id': comment.id,
            'comment': comment.comment 
        }


    @required_login('user.posts.comments.update')
    def put(self, user, post_id, comment_id):
        """
        PUT /api/posts/<post_id>/comments

        지정된 게시물의 댓글을 수정함.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `user.posts.comments.update`. 권한이 없는 경우 `403 - Forbidden` 반환.
        작성자와 로그인한 유저가 다른경우 `admin.posts.comments.update` 권한이 있을 경우에만 수정이 가능합니다.

        parameters:
            - comment: 댓글 내용.

        returns:
            - message: 상태 메세지.
        """
        post = Post.from_id(post_id)
        msg = utils.get_post_argument('comment', is_required=True)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        comment = post.find_comment_by_id(comment_id)

        if comment is None:
            raise NotFound('Comment ID %d is not found.' % comment_id)


        if comment.writer.uid != user.uid and not user.has_permission('admin.posts.comments.update'):
            raise BadRequest('Operation not permitted.')

        comment.comment = msg

        return { 'message': 'Success' }


    @required_login('user.posts.comments.delete')
    def delete(self, user, post_id, comment_id):
        """
        DELETE /api/posts/<post_id>/comments

        지정된 게시물의 댓글을 삭제.

        로그인 전용 메서드. 로그인 하지 않은 경우 `401 - Unauthorized` 반환.

        권한 요구: `user.posts.comments.delete`. 권한이 없는 경우 `403 - Forbidden` 반환.
        작성자와 로그인한 유저가 다른경우 `admin.posts.comments.delete` 권한이 있을 경우에만 삭제가 가능합니다.

        returns:
            - message: 상태 메세지.
        """
        post = Post.from_id(post_id)

        if post is None:
            raise NotFound('Post ID %d is not found.' % post_id)

        comment = post.find_comment_by_id(comment_id)

        if comment is None:
            raise NotFound('Comment ID %d is not found.' % comment_id)

        if comment.writer.uid != user.uid and not user.has_permission('admin.posts.comments.delete'):
            raise BadRequest('Operation not permitted.')

        comment.delete()

        return { 'message': 'Success' }
