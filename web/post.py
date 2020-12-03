from flask import url_for

from . import database
from .user import User

class Location:
    def __init__(self, lat, lng):
        self.__lat = float(lat)
        self.__lng = float(lng)
    

    @property
    def lat(self):
        return self.__lat

    
    @lat.setter
    def lat(self, value):
        self.__lat = value
    

    @property
    def lng(self):
        return self.__lng
    

    @lng.setter
    def lng(self, value):
        self.__lng = value
    
    
    def __lt__(self, other):
        if isinstance(other, Location):
            return self.lat < other.lat and self.lng < self.lng
        else:
            return False

    
    def __le__(self, other):
        return not self.__gt__(other)


    def __gt__(self, other):
        if isinstance(other, Location):
            return self.lat > other.lat and self.lng > self.lng
        else:
            return False


    def __ge__(self, other):
        return not self.__lt__(other)


    def __eq__(self, other):
        if isinstance(other, Location):
            return self.lat == other.lat and self.lng == self.lng
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Post:
    """
    게시글을 나타내는 클래스.
    """
    def __sync_data(self):
        database.update_post(self.__id, self.__name, self.__addr, self.__loc, self.__url, self.__content, self.__category)


    def __init__(self, data):
        self.__writer_id = data['user_uid']
        self.__id = data['post_id']
        self.__name = data['post_name']
        self.__addr = data['post_address']
        self.__loc = Location(data['post_lat'], data['post_lng'])
        self.__url = data['post_image_url']
        self.__content = data['post_content']
        self.__category = data['post_category']


    @property
    def id(self):
        return self.__id


    @property
    def writer(self):
        return User.from_uid(self.__writer_id)

    
    @property
    def name(self):
        return self.__name

    
    @name.setter
    def name(self, value):
        self.__name = value

        self.__sync_data()
    

    @property
    def address(self):
        return self.__addr


    @address.setter
    def address(self, value):
        self.__addr = value

        self.__sync_data()


    @property
    def location(self):
        return self.__loc


    @location.setter
    def location(self, value):
        self.__loc = value

        self.__sync_data()
    

    @property
    def picture_url(self):
        return self.__url
    

    @picture_url.setter
    def picture_url(self, value):
        from .api import resources_api
        
        if value is None or not resources_api.is_valid_url(value):
            value = url_for('static', filename='images/default_post.svg')
        
        self.__url = value

        self.__sync_data()
    

    @property
    def content(self):
        return self.__content

    
    @content.setter
    def content(self, value):
        self.__content = value

        self.__sync_data()

    
    @property
    def category(self):
        return self.__category

    
    @category.setter
    def category(self, value):
        self.__category = value

        self.__sync_data()

    def get_recommend(self, user_uid):
        return database.is_user_recommended(self.id, user_uid)


    def set_recommend(self, user_uid, recommend):
        if recommend:
            database.add_recommend(self.id, user_uid)
        else:
            database.remove_recommend(self.id, user_uid)

    
    def write_comment(self, user, comment):
        database.create_comment(self.id, user.uid, comment)


    def get_comments(self, start, count):
        return [ Comment(data) for data in database.get_comments(self.id, start, count) ]


    def find_comment_by_id(self, comment_id):
        data = database.get_comment(comment_id)

        return Comment(data) if data is not None else None
    

    def get_recommend_count(self):
        return database.get_recommend_count(self.id)
    

    def delete(self):
        database.delete_post(self.id)


    @staticmethod
    def from_id(id):
        data = database.get_post(id)

        return Post(data) if data is not None else None

    @staticmethod
    def query_by_name(name: str):
        name = name.strip()

        return [ Post(data) for data in database.find_posts_by_name(name) ]
    

    @staticmethod
    def query_by_category(category: str):
        category = category.strip()

        return [ Post(data) for data in database.find_posts_by_category(category) ]


    @staticmethod
    def query_by_location(start, end):
        return [ Post(data) for data in database.find_posts_by_location(start, end) ]


    @staticmethod
    def get_posts(start, count):
        return [ Post(data) for data in database.get_posts(start, count) ]
    

    @staticmethod
    def get_posts_by_recommends(start, count):
        return [ Post(data) for data in database.get_posts_by_recommends(start, count) ]


    @staticmethod
    def create_post(user, name, addr, loc, picture_url, content, category):
        from .api import resources_api
        
        if picture_url is None or not resources_api.is_valid_url(picture_url):
            picture_url = url_for('static', filename='images/default_post.svg')

        database.create_post(user.uid, name, addr, loc, picture_url, content, category)


class CommentWriter:
    """
    댓글 작성자를 나타내는 클래스.
    """
    def __init__(self, uid, nickname, profile_url):
        self.__uid = uid
        self.__nickname = nickname
        self.__profile_url = profile_url

    @property
    def uid(self):
        return self.__uid

    
    @property
    def nickname(self):
        return self.__nickname

    
    @property
    def profile_url(self):
        return self.__profile_url


class Comment:
    """
    댓글을 나타내는 클래스.
    """
    def __sync_data(self):
        database.update_comment(self.id, self.comment)


    def __init__(self, data):
        self.__writer = data['user_uid']
        self.__id = data['comment_id']
        self.__comment = data['comment']
    

    @property
    def comment(self):
        return self.__comment
    

    @comment.setter
    def comment(self, value):
        self.__comment = value

        self.__sync_data()
    

    @property
    def writer(self):
        return User.from_uid(self.__writer)
    

    @property
    def id(self):
        return self.__id


    def delete(self):
        database.delete_comment(self.id)


    @staticmethod
    def create_comment(user, post_id, comment):
        database.create_comment(post_id, user.uid, comment)