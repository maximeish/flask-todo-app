from flask.globals import session
import jwt
import json
import datetime

import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from flask_marshmallow import Marshmallow

auth_blueprint = Blueprint('auth', __name__)

app = Flask(__name__)
CORS(app)

app_settings = os.getenv(
    'APP_SETTINGS',
    'config.DevelopmentConfig'
)
app.config.from_object(app_settings)
ma = Marshmallow(app)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=5),
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
            payload = jwt.decode(auth_token, app.config.get(
                'SECRET_KEY'), algorithms=['HS256'])
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except Exception as e:
            print(e)
            return 'Invalid token. Please log in again.'


class Task(db.Model):
    """ Task Model for storing tasks for users """
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    u_id = db.Column(db.Integer, unique=False, nullable=False)
    task = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(255), nullable=False)

    def __init__(self, u_id, task, status):
        self.u_id = u_id
        self.task = task
        self.status = status
    # def get_tasks(self, u_id):


class TaskSchema(ma.Schema):
    class Meta:
        fields = ('status', 'task', 'u_id', 'id')


task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)


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


class SignupAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        try:
            user = User.query.filter_by(email=post_data.get('email')).first()
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Provide email and password'
            }
            return make_response(jsonify(responseObject)), 401

        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                print('now encoding token')
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                print('received auth_token ', auth_token)
                responseObject = {
                    'status': 'success',
                    'message': 'User with id {0} successfully registered.'.format(user.decode_auth_token(auth_token)),
                    'auth_token': auth_token
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Error in signing up user'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid email and password'
            }
            return make_response(jsonify(responseObject)), 500


class UserAPI(MethodView):
    """
    User Resource
    """

    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class LogoutAPI(MethodView):
    """
    Logout Resource
    """

    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class AddTaskAPI(MethodView):
    def post(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''

        if auth_token:
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                try:
                    user = User.query.filter_by(id=resp).first()
                    user_id = resp
                    post_data = request.get_json()
                    task_desc = post_data.get('task_description')
                    task_status = post_data.get('task_status')

                    task = Task(user_id, task_desc, task_status)

                    # insert the task
                    db.session.add(task)
                    db.session.commit()

                    responseObject = {
                        'status': 'success',
                        'message': 'Task created successfully for user with id {0}'.format(user.decode_auth_token(auth_token)),
                    }
                    return make_response(jsonify(responseObject)), 201
                except Exception as e:
                    print(e)
                    responseObject = {
                        'status': 'fail',
                        'message': 'Please provide task_description and task_status',
                    }
                    return make_response(jsonify(responseObject)), 401

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class RetrieveTasksAPI(MethodView):
    def post(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''

        if auth_token:
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                try:
                    user = User.query.filter_by(id=resp).first()
                    tasks = Task.query.filter_by(u_id=resp).all()
                    tasksSer = tasks_schema.dump(tasks)

                    responseObject = {
                        'status': 'success',
                        'message': 'Retrieved tasks for user with id {0}'.format(user.decode_auth_token(auth_token)),
                        'tasks': tasksSer
                    }
                    return make_response(jsonify(responseObject)), 201
                except Exception as e:
                    print(e)
                    responseObject = {
                        'status': 'fail',
                        'message': 'Error decoding token',
                    }
                    return make_response(jsonify(responseObject)), 401

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class UpdateTaskAPI(MethodView):
    def patch(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''

        if auth_token:
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                try:
                    user_id = resp
                    post_data = request.get_json()
                    task_id = post_data.get('task_id')

                    if not post_data.get('task_status') and not post_data.get('task_text'):
                        raise Exception(
                            'Neither task_status nor task_text are provided')

                    task = Task.query.filter_by(id=task_id).first()
                    print(task.u_id)

                    if task and (task.u_id == user_id):
                        print('success')
                        try:
                            if post_data.get('task_text'):
                                task.task = post_data.get('task_text')

                            if post_data.get('task_status'):
                                task.status = post_data.get('task_status')

                            db.session.commit()

                            tasksSer = task_schema.dump(task)

                            responseObject = {
                                'status': 'success',
                                'message': 'Task with id {0} updated successfully'.format(task.id),
                                'task': tasksSer
                            }
                            return make_response(jsonify(responseObject)), 201
                        except Exception as e:
                            print(e)
                            responseObject = {
                                'status': 'fail',
                                'message': 'Error updating task with id {0}'.format(task.id)
                            }
                            return make_response(jsonify(responseObject)), 401
                    else:
                        responseObject = {
                            'status': 'fail',
                            'message': 'Please provide a valid task_id and your id should match that of the user who created the task',
                        }
                        return make_response(jsonify(responseObject)), 401
                except Exception as e:
                    print(e)
                    responseObject = {
                        'status': 'fail',
                        'message': 'Please provide task_id and task_status or task_text',
                    }
                    return make_response(jsonify(responseObject)), 401

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class DeleteTaskAPI(MethodView):
    def delete(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''

        if auth_token:
            resp = User.decode_auth_token(auth_token)

            if not isinstance(resp, str):
                try:
                    user_id = resp
                    post_data = request.get_json()
                    task_id = post_data.get('task_id')

                    task = Task.query.filter_by(id=task_id).first()

                    if task and (task.u_id == user_id):
                        try:
                            Task.query.filter_by(id=task_id).delete()

                            db.session.commit()

                            tasksSer = task_schema.dump(task)

                            responseObject = {
                                'status': 'success',
                                'message': 'Task with id {0} deleted'.format(task_id)
                            }
                            return make_response(jsonify(responseObject)), 201
                        except Exception as e:
                            print(e)
                            responseObject = {
                                'status': 'fail',
                                'message': 'Error deleting task with id {0}'.format(task.id)
                            }
                            return make_response(jsonify(responseObject)), 401
                    else:
                        responseObject = {
                            'status': 'fail',
                            'message': 'Please provide a valid task_id and your id should match that of the user who created the task',
                        }
                        return make_response(jsonify(responseObject)), 401
                except Exception as e:
                    print(e)
                    responseObject = {
                        'status': 'fail',
                        'message': 'Please provide task_id',
                    }
                    return make_response(jsonify(responseObject)), 401

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


# define the API resources
registration_view = SignupAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# task operations resources
add_task = AddTaskAPI.as_view('add_task_api')
retrieve_tasks = RetrieveTasksAPI.as_view('retrieve_tasks_api')
update_task = UpdateTaskAPI.as_view('update_task_api')
delete_task = DeleteTaskAPI.as_view('delete_task_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/api/signup',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/api/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/api/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/api/logout',
    view_func=logout_view,
    methods=['POST']
)

# task operations
auth_blueprint.add_url_rule(
    '/api/add-task',
    view_func=add_task,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/api/get-all',
    view_func=retrieve_tasks,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/api/update-task',
    view_func=update_task,
    methods=['PATCH']
)
auth_blueprint.add_url_rule(
    '/api/delete',
    view_func=delete_task,
    methods=['DELETE']
)


@app.route('/api')
def index():
    return make_response(
        jsonify({"message": "Welcome to 2Do"}),
        200,
    )

# 404 Not Found


@app.errorhandler(404)
def not_found(error):
    response = make_response(
        jsonify({"message": "Not Found"}),
        404,
    )
    return response


app.register_blueprint(auth_blueprint)

if __name__ == '__main__':
    app.run()
