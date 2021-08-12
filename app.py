from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, Response
from validate_email import validate_email
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import jwt


app = Flask(__name__)
app.config['SECRET_KEY'] = '0Gvdupzgh6'
app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://itmo:itmo@localhost/itmo_lock'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    surname = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    token = db.Column(db.String)
    is_admin = db.Column(db.Boolean)

    def __repr__(self):
        return '<Users %r>' % self.id


class Locks(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    number = db.Column(db.String)
    preview = db.Column(db.String)
    about = db.Column(db.String)
    token = db.Column(db.String)

    def __repr__(self):
        return '<Locks %r>' % self.id


class Access(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    id_user = db.Column(db.Integer)
    id_lock = db.Column(db.Integer)

    def __repr__(self):
        return '<Access %r>' % self.id


@app.route('/v1/auth/registration', methods=['POST'])
def registration():
    values = request.json
    if 'email' in values.keys() and 'name' in values.keys() and 'surname' in values.keys() and 'password' in values.keys() and validate_email(values['email']):
        token = jwt.encode({
                'email': values['email'],
                'time': str(datetime.utcnow())
            }, key = app.config['SECRET_KEY'])
        user = Users(name=values['name'], surname=values['surname'], email=values['email'], password=generate_password_hash(values['password']), token=token, is_admin=False)
        try:
            db.session.add(user)
            db.session.commit()
            return Response(json.dumps({
                    'token': token}))
        except:
            return Response("invalid input", status=400, mimetype='application/json')
    else:
        return Response("invalid input", status=400, mimetype='application/json')


@app.route('/v1/auth/login', methods=['POST'])
def login():
    values = request.json
    if 'email' in values.keys() and 'password' in values.keys():
        user = Users.query.filter_by(email=values['email']).first()
        if user == None:
            return Response("Wrong email", status=400, mimetype='application/json')
        else:
            if check_password_hash(user.password, values['password']):
                return user.token
            else:
                return Response("Wrong password", status=400, mimetype='application/json')
    else:
        return Response("Invalid input", status=400, mimetype='application/json')


@app.route('/v1/locks/<int:id>/add_user', methods=['POST'])
def add_user(id):
    token = request.headers.get('Authorization')
    user = Users.query.filter_by(token=token).first()
    if user is None:
        return Response("Unauthorized user", status=400, mimetype='application/json')
    else:
        if user.is_admin:
            values = request.json
            access = Access(id_user=values['id'], id_lock=id)
            try:
                db.session.add(access)
                db.session.commit()
                return Response("Success", status=201, mimetype='application/json')
            except:
                return Response("Invalid input", status=400, mimetype='application/json')
        else:
            return Response("Permission denied", status=400, mimetype='application/json')


@app.route('/v1/locks/<int:id>/remove_user', methods=['POST'])
def remove_user(id):
    token = request.headers.get('Authorization')
    user = Users.query.filter_by(token=token).first()
    if user is None:
        return Response("Unauthorized user", status=400, mimetype='application/json')
    else:
        if user.is_admin:
            values = request.json
            access = Access.query.filter_by(id_user=values['id'], id_lock=id).first()
            try:
                db.session.delete(access)
                db.session.commit()
                return Response("Success", status=200, mimetype='application/json')
            except:
                return Response("Invalid input", status=400, mimetype='application/json')
        else:
            return Response("Permission denied", status=400, mimetype='application/json')


@app.route('/v1/locks', methods=['GET'])
def get_locks():
    token = request.headers.get('Authorization')
    user = Users.query.filter_by(token=token).first()
    if user is None:
        return Response("Unauthorized user", status=400, mimetype='application/json')
    else:
        if user.is_admin:
            locks = Locks.query.all()
            locks_list = []
            for i in range(len(locks)):
                locks_list.append({
                    "id": locks[i].id,
                    "number": locks[i].number,
                    "preview": locks[i].preview,
                    "about": locks[i].about
                })
            return Response(json.dumps({"locks": locks_list}))
        else:
            locks = Locks.query.filter_by(id=user.id).all()
            locks_list = []
            for i in range(len(locks)):
                locks_list.append({
                    "id": locks[i].id,
                    "number": locks[i].number,
                    "preview": locks[i].preview,
                    "about": locks[i].about
                })
            return Response(json.dumps({"locks": locks_list}))


@app.route('/v1/locks/<int:id>/token', methods=['GET'])
def get_lock_token(id):
    token = request.headers.get('Authorization')
    user = Users.query.filter_by(token=token).first()
    if user is None:
        return Response("Unauthorized user", status=400, mimetype='application/json')
    else:
        if user.is_admin:
            lock = Locks.query.get_or_404(id)
            return Response(json.dumps({
                "token": lock.token
            }))
        else:
            access = Access.query.filter_by(id_user=user.id, id_lock=id).first()
            if access is None:
                return Response("Permission denied", status=400, mimetype='application/json')
            else:
                lock = Locks.query.get_or_404(id)
                return Response(json.dumps({
                    "token": lock.token
                }))


@app.route('/v1/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')
    user = Users.query.filter_by(token=token).first()
    if user is None:
        return Response("Unauthorized user", status=400, mimetype='application/json')
    else:
        if user.is_admin:
            users = Users.query.all()
            users_list = []
            for i in range(len(users)):
                accessible_locks_id = []
                accessible_locks = Access.query.filter_by(id_user=users[i].id).all()
                for j in range(len(accessible_locks)):
                    accessible_locks_id.append(accessible_locks[j].id_lock)
                users_list.append({
                    "id": users[i].id,
                    "name": users[i].name,
                    "surname": users[i].surname,
                    "locks": accessible_locks_id
                })
            return Response(json.dumps({"users": users_list}))
        else:
            return Response("Permission denied", status=400, mimetype='application/json')


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)