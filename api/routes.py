# from flask import Flask, jsonify, make_response, request, redirect, session
# import jwt
# from functools import wraps

# # from controllers.add_item import add_item

# app = Flask(__name__)
# app.config['SECRET_KEY'] = '7Qgy6d-yNcWTINRnIEe1V26hdDWRmjiw'
# app.app_context()


# # def check_auth(unused):
# #     if session.get('logged_in'):
# #         return redirect('/todo')


# def token_required(func):
#     # decorator factory which invoks update_wrapper() method and passes decorated function as an argument

#     @wraps(func)
#     def decorated(*args, **kwargs):
#         token = request.args.get('token')
#         if not token:
#             return jsonify({'Alert!': 'Token is missing!'}), 401

#         try:

#             data = jwt.decode(token, app.config['SECRET_KEY'])
#         # You can use the JWT errors in exception
#         # except jwt.InvalidTokenError:
#         #     return 'Invalid token. Please log in again.'
#         except:
#             return jsonify({'Message': 'Invalid token'}), 403
#         return func(*args, **kwargs)
#     return decorated


# @app.route('/auth')
# @token_required
# def auth():
#     return 'JWT is verified. Welcome to your dashboard !'


# @app.route('/')
# def home():
#     if session.get('logged_in'):
#         return redirect('/todo')
#     return make_response(
#         jsonify({"message": "Welcome :)"}),
#         200,
#     )


# # route to sign up
# @app.route("/signup", methods=["POST"])
# # @check_auth
# def signup():
#     auth = request.authorization
#     if not auth or not auth.username or not auth.password:
#         return make_response(
#             jsonify({"error": "Missing credentials"}),
#             401,
#         )
#     if auth.username and auth.password:


#     return 0


# # route to login
# @app.route("/login", methods=["POST"])
# # @check_auth
# def login():
#     if session.get('logged_in'):
#         return redirect('/todo')

#     auth = request.authorization
#     if not auth or not auth.username or not auth.password:
#         return make_response(
#             jsonify({"error": "Missing credentials"}),
#             401,
#         )
#     return 0


# # fetch items
# @app.route("/fetch")
# # @token_required
# def fetch_items():
#     response = make_response(
#         jsonify({
#             "items": [{
#                 "id": 1,
#                 "name": "item1"
#             }, {
#                 "id": 2,
#                 "name": "item2"
#             }]
#         }),
#         200,
#     )
#     return response

# # add item


# @app.route("/add<item>")
# @token_required
# def add_item(item):
#     response = make_response(
#         jsonify({"items": ["item1", "item2", "item3", item]}),
#         200,
#     )
#     response.headers["Content-Type"] = "application/json"
#     return response

# # update item


# @app.route("/update<int:id>&<state>")
# @token_required
# def update_item(id, state):
#     response = make_response(
#         jsonify({"message": id}),
#         200,
#     )
#     response.headers["Content-Type"] = "application/json"
#     return response

# # delete item


# @app.route("/delete<int:id>")
# @token_required
# def delete_item(id):
#     response = make_response(
#         jsonify({"message": id}),
#         200,
#     )
#     response.headers["Content-Type"] = "application/json"
#     return response


# # app.add_url_rule("/add<name>", "add", add_item)
# # app.add_url_rule("/fetch", "fetch", add_item)
# # app.add_url_rule("/update", "update", add_item)
# # app.add_url_rule("/delete", "delete", add_item)

# # 404 Not Found
# @app.errorhandler(404)
# def not_found(error):
#     response = make_response(
#         jsonify({"message": "Not Found"}),
#         404,
#     )
#     response.headers["Content-Type"] = "application/json"
#     return response


# if __name__ == "__main__":
#     app.run(debug=True)


from flask import Flask, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////mnt/c/Users/antho/Documents/todo/todo.db'

db = SQLAlchemy(app)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200))
    complete = db.Column(db.Boolean)


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = password
        # bcrypt.generate_password_hash(
        #     password, app.config.get('BCRYPT_LOG_ROUNDS')
        # ).decode()

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class Task(db.Model):
    """ Task Model for storing tasks for users """
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    u_id = db.Column(db.Integer, unique=False, nullable=False)
    task = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, u_id, task, status=False):
        self.u_id = u_id
        self.task = task
        self.status = status


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


@app.route('/')
def index():
    return make_response(
        jsonify({"message": "Welcome :)"}),
        200,
    )


@app.route('/add', methods=['POST'])
def add():
    todo = Todo(text=request.form['todoitem'], complete=False)
    db.session.add(todo)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/complete/<id>')
def complete(id):

    todo = Todo.query.filter_by(id=int(id)).first()
    todo.complete = True
    db.session.commit()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
