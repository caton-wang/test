#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
from flask import Flask, jsonify, request, make_response, abort, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from config import config


app = Flask(__name__)
app.config.from_object(config['default'])
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


# database section


class Province(db.Model):
    __tablename__ = 'provinces'
    id = db.Column(db.Integer, primary_key=True)
    province_name = db.Column(db.String(32), unique=True)
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, province_name, created_by_admin, comments):
        self.province_name = province_name
        self.created_by_admin = created_by_admin
        self.comments = comments

    def to_json(self):
        json_province ={
            'id': self.id,
            'province_name': self.province_name,
            'comments': self.comments,
        }
        return json_province

    def __repr__(self):
        return self.province_name


class City(db.Model):
    __tablename__ = 'cities'
    id = db.Column(db.Integer, primary_key=True)
    city_name = db.Column(db.String(64), unique=True)
    province_id = db.Column(db.Integer, db.ForeignKey('provinces.id'))
    province = db.relationship('Province', backref=db.backref('cities', lazy='dynamic'))
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, city_name, province_id, created_by_admin, comments):
        self.city_name = city_name
        self.province_id = province_id
        self.created_by_admin = created_by_admin
        self.comments = comments

    def to_json(self):
        json_city = {
            'id': self.id,
            'city_name': self.city_name,
            'province_id': self.province_id,
            'comments': self.comments,
        }
        return json_city

    def __repr__(self):
        return self.city_name


class County(db.Model):
    __tablename__ = 'counties'
    id = db.Column(db.Integer, primary_key=True)
    county_name = db.Column(db.String(64), unique=True)
    city_id = db.Column(db.Integer, db.ForeignKey('cities.id'))
    city = db.relationship('City', backref=db.backref('counties', lazy='dynamic'))
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, county_name, city_id, created_by_admin, comments):
        self.county_name = county_name
        self.city_id = city_id
        self.created_by_admin = created_by_admin
        self.comments = comments

    def to_json(self):
        json_county = {
            'id': self.id,
            'county_name': self.county_name,
            'city_id': self.city_id,
            'comments': self.comments
        }
        return json_county

    def __repr__(self):
        return self.county_name


class Street(db.Model):
    __tablename__ = 'streets'
    id = db.Column(db.Integer, primary_key=True)
    street_name = db.Column(db.String(128), unique=True)
    county_id = db.Column(db.Integer, db.ForeignKey('counties.id'))
    county = db.relationship('County', backref=db.backref('streets', lazy='dynamic'))
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, street_name, county_id, created_by_admin, comments):
        self.street_name = street_name
        self.county_id = county_id
        self.created_by_admin = created_by_admin
        self.comments = comments

    def to_json(self):
        json_street = {
            'id': self.id,
            'street_name': self.street_name,
            'county_id': self.county_id,
            'comments': self.comments
        }
        return json_street

    def __repr__(self):
        return self.street_name


class Community(db.Model):
    __tablename__ = 'communities'
    id = db.Column(db.Integer, primary_key=True)
    community_name = db.Column(db.String(128), unique=True)
    street_id = db.Column(db.Integer, db.ForeignKey('streets.id'))
    street = db.relationship('Street',backref=db.backref('communities', lazy='dynamic') )
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, community_name, street_id, created_by_admin, comments):
        self.community_name = community_name
        self.street_id = street_id
        self.created_by_admin = created_by_admin
        self.comments = comments

    def to_json(self):
        json_community = {
            'id': self.id,
            'community_name': self.community_name,
            'street_id': self.street_id,
            'comments': self.comments,
        }
        return json_community

    def __repr__(self):
        return self.community_name


class Door(db.Model):
    __tablename__ = 'doors'
    id = db.Column(db.Integer, primary_key=True)
    door_name = db.Column(db.String(32), unique=True, nullable=False)
    serial_number = db.Column(db.String(128), unique=True, nullable=False)
    hw_door_key = db.Column(db.String(128), unique=True, nullable=False)
    public_door = db.Column(db.Boolean, default=False)
    building = db.Column(db.String(32))
    unit = db.Column(db.String(16))
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'))
    community = db.relationship('Community', backref=db.backref('doors', lazy='dynamic'))
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def __init__(self, door_name, serial_number, hw_door_key, public_door, building, unit, community_id,
                 created_by_admin, comments):
        self.door_name = door_name
        self.serial_number = serial_number
        self.hw_door_key = hw_door_key
        self.public_door = public_door
        self.building = building
        self.unit = unit
        self.community_id = community_id
        self.created_by_admin = created_by_admin
        self.comments = comments

    def cal_hw_door_key(self, hw_door_key=None):

        if hw_door_key is None:
            pass

    def to_json(self):
        json_door = {
            'id': self.id,
            'door_name': self.door_name,
            'serial_number': self.serial_number,
            'hw_door_key': self.hw_door_key,
            'public_door': self.public_door,
            'building': self.building,
            'unit': self.unit,
            'community_id': self.community_id,
            'comments': self.comments
        }
        return json_door

    def __repr__(self):
        return self.door_name


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    active = db.Column(db.Boolean, default=True)
    real_name = db.Column(db.String(32))
    user_mobile = db.Column(db.String(16), unique=True)
    user_room = db.Column(db.String(32))
    user_type = db.Column(db.String(32))
    door_can_open = db.Column(db.String(256), nullable=False)
    transfer_door_perm = db.Column(db.Boolean, default=False)
    created_by_admin = db.Column(db.String(16))
    user_role = db.Column(db.String(16))
    member_since = db.Column(db.DateTime, default=datetime.datetime.now())
    comments = db.Column(db.Text)

    def to_json(self):
        json_user = {
            'id': self.id,
            'username': self.username,
            'active': self.active,
            'real_name': self.real_name,
            'user_mobile': self.user_mobile,
            'user_room': self.user_room,
            'user_type': self.user_type,
            'user_role': self.user_role,
            'open_door_perm': self.open_door_perm,
            'transfer_door_perm': self.transfer_door_perm,
            'member_since': self.member_since,
            'comments': self.comments,
        }
        return json_user

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=24*365*3600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


"""
    def is_authenticated(self):
        return True

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def __repr__(self):
        return self.username

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
"""

db.create_all()

# API Section


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Status Code 404 Not Found'}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Status Code 400 Bad Request'}), 400)


@app.route('/v1/provinces', methods=['GET'])
@auth.login_required
def get_provinces():
    provinces = Province.query.all()
    return jsonify({'provinces': [province.to_json() for province in provinces]})


@app.route('/v1/provinces', methods=['POST'])
@auth.login_required
def post_provinces():
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json or not 'province_name' in request.json:
        abort(400)
    province = Province(request.json['province_name'], 'superadmin', request.json.get('comments', ''))
    db.session.add(province)
    db.session.commit()
    return jsonify({'province': province.province_name + ' created successfully'}), 201


@app.route('/v1/provinces/<int:id>', methods=['GET'])
@auth.login_required
def get_province(id):
    province = Province.query.get_or_404(id)
    return jsonify(province.to_json())


@app.route('/v1/provinces/<int:id>', methods=['PUT'])
@auth.login_required
def put_province(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json:
        abort(400)
    province = Province.query.get_or_404(id)
    province.province_name = request.json.get('province_name', province.province_name)
    province.comments = request.json.get('comments', province.comments)
    db.session.commit()
    return jsonify({'province': 'updated successfully'})


@app.route('/v1/provinces/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_province(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    province = Province.query.get_or_404(id)
    db.session.delete(province)
    db.session.commit()
    return jsonify({'province': province.province_name + ' deleted successfully'})


@app.route('/v1/cities', methods=['GET'])
@auth.login_required
def get_cities():
    cities = City.query.all()
    return jsonify({'cities': [city.to_json() for city in cities]})


@app.route('/v1/cities', methods=['POST'])
@auth.login_required
def post_cities():
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json or not 'city_name' in request.json or not 'province_id' in request.json:
        abort(400)
    city = City(request.json['city_name'], request.json['province_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(city)
    db.session.commit()
    return jsonify({'city': city.city_name + ' created successfully'}), 201


@app.route('/v1/cities/<int:id>', methods=['GET'])
@auth.login_required
def get_city(id):
    city = City.query.get_or_404(id)
    return jsonify(city.to_json())


@app.route('/v1/cities/<int:id>', methods=['PUT'])
@auth.login_required
def put_city(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json:
        abort(400)
    city = City.query.get_or_404(id)
    city.city_name = request.json.get('city_name', city.city_name)
    city.province_id = request.json.get('province_id', city.province_id)
    city.comments = request.json.get('comments', city.comments)
    db.session.commit()
    return jsonify({'city': 'updated successfully'})


@app.route('/v1/cities/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_city(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    city = City.query.get_or_404(id)
    db.session.delete(city)
    db.session.commit()
    return jsonify({'city': city.city_name + ' deleted successfully'})


@app.route('/v1/counties', methods=['GET'])
@auth.login_required
def get_counties():
    counties = County.query.all()
    return jsonify({'counties': [county.to_json() for county in counties]})


@app.route('/v1/counties', methods=['POST'])
@auth.login_required
def post_counties():
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json or not 'county_name' in request.json or not 'city_id' in request.json:
        abort(400)
    county = County(request.json['county_name'], request.json['city_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(county)
    db.session.commit()
    return jsonify({'county': county.county_name + ' created successfully'}), 201


@app.route('/v1/counties/<int:id>', methods=['GET'])
@auth.login_required
def get_county(id):
    county = County.query.get_or_404(id)
    return jsonify(county.to_json())


@app.route('/v1/counties/<int:id>', methods=['PUT'])
@auth.login_required
def put_county(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    if not request.json:
        abort(400)
    county = County.query.get_or_404(id)
    county.county_name = request.json.get('county_name', county.county_name)
    county.city_id = request.json.get('city_id', county.city_id)
    county.comments = request.json.get('comments', county.comments)
    db.session.commit()
    return jsonify({'county': 'updated successfully'})


@app.route('/v1/counties/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_county(id):
    if g.user.user_role != 'superadmin':
        abort(403)
    county = County.query.get_or_404(id)
    db.session.delete(county)
    db.session.commit()
    return jsonify({'county': county.county_name + 'deleted successfully'})


@app.route('/v1/streets', methods=['GET'])
@auth.login_required
def get_streets():
    streets = Street.query.all()
    return jsonify({'streets': [street.to_json() for street in streets]})


@app.route('/v1/streets', methods=['POST'])
@auth.login_required
def post_streets():
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json or not 'street_name' in request.json or not 'county_id' in request.json:
        abort(400)
    street = Street(request.json['street_name'], request.json['county_id'], g.user.username, request.json.get('comments', ''))
    db.session.add(street)
    db.session.commit()
    return jsonify({'street': street.street_name + ' created successfully'}), 201


@app.route('/v1/streets/<int:id>', methods=['GET'])
@auth.login_required
def get_street(id):
    street = Street.query.get_or_404(id)
    return jsonify(street.to_json)


@app.route('/v1/streets/<int:id>', methods=['PUT'])
@auth.login_required
def put_street(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json:
        abort(400)
    if g.user.user_role == 'superadmin':
        street = Street.query.get_or_404(id)
    else:
        street = Street.query.filter_by(id=id, created_by_admin=g.user.username).first()

    street.street_name = request.json.get('street_name', street.street_name)
    street.county_id = request.json.get('county_id', street.county_id)
    street.comments = request.json.get('comments', street.comments)
    db.session.commit()
    return jsonify({'street': 'updated successfully'})


@app.route('/v1/streets/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_street(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if g.user.user_role == 'superadmin':
        street = Street.query.get_or_404(id)
    else:
        street = Street.query.filter_by(id=id, created_by_admin=g.user.username).first()

    db.session.delete(street)
    db.session.commit()
    return jsonify({'street': street.street_name + 'deleted successfully'})


@app.route('/v1/communities', methods=['GET'])
@auth.login_required
def get_communities():
    communities = Community.query.all()
    return jsonify({'communities': [community.to_json() for community in communities]})


@app.route('/v1/communities', methods=['POST'])
@auth.login_required
def post_communities():
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json or not 'community_name' in request.json or not 'street_id' in request.json:
        abort(400)
    community = Community(request.json['community_name'], request.json['street_id'], g.user.username, request.json.get('comments', ''))
    db.session.add(community)
    db.session.commit()
    return jsonify({'community': community.community_name + ' created successfully'}), 201


@app.route('/v1/communities/<int:id>', methods=['GET'])
@auth.login_required
def get_community(id):
    community = Community.query.get_or_404(id)
    return jsonify(community.to_json)


@app.route('/v1/communities/<int:id>', methods=['PUT'])
@auth.login_required
def put_community(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json:
        abort(400)
    if g.user.user_role == 'superadmin':
        community = Community.query.get_or_404(id)
    else:
        community = Community.query.filter_by(id=id, created_by_admin=g.user.username).first()

    community.community_name = request.json.get('community_name', community.community_name)
    community.street_id = request.json.get('street_id', community.street_id)
    community.comments = request.json.get('comments', community.comments)
    db.session.commit()
    return jsonify({'community': 'updated successfully'})


@app.route('/v1/communities/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_community(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if g.user.user_role == 'superadmin':
        community = Community.query.get_or_404(id)
    else:
        community = Community.query.filter_by(id=id, created_by_admin=g.user.username).first()
    db.session.delete(community)
    db.session.commit()
    return jsonify({'community': community.community_name + 'deleted successfully'})


@app.route('/v1/doors', methods=['GET'])
@auth.login_required
def get_doors():
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if g.user.user_role == 'superadmin':
        doors = Community.query.all()
    else:
        doors = Community.query.filter_by(created_by_admin=g.user.username)

    return jsonify({'doors': [door.to_json() for door in doors]})


@app.route('/v1/doors', methods=['POST'])
@auth.login_required
def post_doors():
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json or not 'door_name' in request.json or not 'serial_number' in request.json \
            or not 'hw_door_key' in request.json or not 'public_door' in request.json or not 'building' in \
            request.json or not 'unit' in request.json or not 'community_id' in request.json:
        abort(400)
    door = Door(request.json['door_name'], request.json['serial_number'], request.json['hw_door_key'], \
                request.json['public_door'], request.json['building'], request.json['unit'], \
                request.json['community_id'], g.user.username, request.json.get('comments', ''))
    db.session.add(door)
    db.session.commit()
    return jsonify({'door': door.door_name + ' created successfully'}), 201


@app.route('/v1/doors/<int:id>', methods=['GET'])
@auth.login_required
def get_door(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if g.user.user_role == 'superadmin':
        door = Door.query.get_or_404(id)
    else:
        door = Door.query.filter_by(id=id, created_by_admin=g.user.username)
    return jsonify(door.to_json)


@app.route('/v1/door/<int:id>', methods=['PUT'])
@auth.login_required
def put_door(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json:
        abort(400)
    if g.user.user_role == 'superadmin':
        door = Door.query.get_or_404(id)
    else:
        door = Door.query.filter_by(id=id, created_by_admin=g.user.username)

    door.door_name = request.json.get('door_name', door.door_name)
    door.serial_number = request.json.get('serial_number', door.serial_number)
    door.hw_door_key = request.json.get('hw_door_key', door.hw_door_key)
    door.public_door = request.json.get('public_door', door.public_door)
    door.building = request.json.get('building', door.building)
    door.unit = request.json.get('unit', door.unit)
    door.community_id = request.json.get('community_id', door.community_id)
    door.comments = request.json.get('comments', door.coments)
    db.session.commit()
    return jsonify({'door': 'updated successfully'})


@app.route('/v1/door/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_door(id):
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if g.user.user_role == 'superadmin':
        door = Door.query.get_or_404(id)
    else:
        door = Door.query.filter_by(id=id, created_by_admin=g.user.username)

    db.session.delete(door)
    db.session.commit()
    return jsonify({'door': door.door_name + 'deleted successfully'})


@app.route('/v1/users', methods=['POST'])
@auth.login_required
def post_users():
    if g.user.user_role != 'superadmin' or g.user.user_role != 'admin':
        abort(403)
    if not request.json or not 'username' in request.json or not 'password' in request.json \
            or not 'user_mobile' in request.json or not 'user_room' in request.json or not \
            'user_type' in request.json or not 'door_can_open' in request.json or not \
            'transfer_door_perm' in request.json or not 'user_role' in request.json:
        abort(400)
    username = request.json.get('username')
    password = request.json.get('password')

    if User.query.filter_by(username=username).first() is not None:
        abort(400)

    user = User(username=username, active=request.json.get('active', ''), real_name=request.json.get('real_name'),
                user_mobile=request.json['user_mobile'], user_room=request.json['user_room'],
                user_type=request.json['user_type'], open_door_perm=request.json['door_can_open'],
                transfer_door_perm=request.json['transfer_door_perm'], created_by_admin=g.user.username,
                user_role=request.json['user_role'], member_since=request.json.get('member_since'),
                comments=request.json.get('comments'))
    user.hash_password(password)
    db.session.add(user)
    db.session.commmit()
    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/v1/user/<int:id>', methods=['GET'])
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/v1/token', methods=['GET'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(24*365*3600)
    return jsonify({'token': token.decode('ascii'), 'duration': 24*365*3600})


@app.route('/v1/user/resource', methods=['GET'])
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

if __name__ == '__main__':
    app.run(debug=True)
