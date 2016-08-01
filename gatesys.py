#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
from flask import Flask, jsonify, request, make_response, abort, json, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager,
from werkzeug.security import generate_password_hash, check_password_hash
from config import config


app = Flask(__name__)
app.config.from_object(config['default'])
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view


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


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    active = db.Column(db.Boolean, default=True)
    real_name = db.Column(db.String(32))
    user_mobile = db.Column(db.String(16), unique=True)
    user_room = db.Column(db.String(32))
    user_type = db.Column(db.String(32))
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
            'member_since': self.member_since,
            'comments': self.comments,
        }
        return json_user

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

db.create_all()

# API Section


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Status Code 404 Not Found'}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Status Code 400 Bad Request'}), 400)


@app.route('/v1/provinces', methods=['GET'])
def get_provinces():
    provinces = Province.query.all()
    return jsonify({'provinces': [province.to_json() for province in provinces]})


@app.route('/v1/provinces', methods=['POST'])
def post_provinces():
    if not request.json or not 'province_name' in request.json:
        abort(400)
    province = Province(request.json['province_name'], 'superadmin', request.json.get('comments', ''))
    db.session.add(province)
    db.session.commit()
    return jsonify({'province': province.province_name + ' created successfully'}), 201


@app.route('/v1/provinces/<int:id>', methods=['GET'])
def get_province(id):
    province = Province.query.get_or_404(id)
    return jsonify(province.to_json())


@app.route('/v1/provinces/<int:id>', methods=['PUT'])
def put_province(id):

    if not request.json:
        abort(400)
    province = Province.query.get_or_404(id)
    province.province_name = request.json.get('province_name', province.province_name)
    province.comments = request.json.get('comments', province.comments)
    db.session.commit()
    return jsonify({'province': 'updated successfully'})


@app.route('/v1/provinces/<int:id>', methods=['DELETE'])
def delete_province(id):
    province = Province.query.get_or_404(id)
    db.session.delete(province)
    db.session.commit()
    return jsonify({'province': province.province_name + ' deleted successfully'})


@app.route('/v1/cities', methods=['GET'])
def get_cities():
    cities = City.query.all()
    return jsonify({'cities': [city.to_json() for city in cities]})


@app.route('/v1/cities', methods=['POST'])
def post_cities():
    if not request.json or not 'city_name' in request.json or not 'province_id' in request.json:
        abort(400)
    city = City(request.json['city_name'], request.json['province_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(city)
    db.session.commit()
    return jsonify({'city': city.city_name + ' created successfully'}), 201


@app.route('/v1/cities/<int:id>', methods=['GET'])
def get_city(id):
    city = City.query.get_or_404(id)
    return jsonify(city.to_json())


@app.route('/v1/cities/<int:id>', methods=['PUT'])
def put_city(id):

    if not request.json:
        abort(400)
    city = City.query.get_or_404(id)
    city.city_name = request.json.get('city_name', city.city_name)
    city.province_id = request.json.get('province_id', city.province_id)
    city.comments = request.json.get('comments', city.comments)
    db.session.commit()
    return jsonify({'city': 'updated successfully'})


@app.route('/v1/cities/<int:id>', methods=['DELETE'])
def delete_city(id):
    city = City.query.get_or_404(id)
    db.session.delete(city)
    db.session.commit()
    return jsonify({'city': city.city_name + ' deleted successfully'})


@app.route('/v1/counties', methods=['GET'])
def get_counties():
    counties = County.query.all()
    return jsonify({'counties': [county.to_json() for county in counties]})


@app.route('/v1/counties', methods=['POST'])
def post_counties():
    if not request.json or not 'county_name' in request.json or not 'city_id' in request.json:
        abort(400)
    county = County(request.json['county_name'], request.json['city_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(county)
    db.session.commit()
    return jsonify({'county': county.county_name + ' created successfully'}), 201


@app.route('/v1/counties/<int:id>', methods=['GET'])
def get_county(id):
    county = County.query.get_or_404(id)
    return jsonify(county.to_json())


@app.route('/v1/counties/<int:id>', methods=['PUT'])
def put_county(id):
    if not request.json:
        abort(400)
    county = County.query.get_or_404(id)
    county.county_name = request.json.get('county_name', county.county_name)
    county.city_id = request.json.get('city_id', county.city_id)
    county.comments = request.json.get('comments', county.comments)
    db.session.commit()
    return jsonify({'county': 'updated successfully'})


@app.route('/v1/counties/<int:id>', methods=['DELETE'])
def delete_county(id):
    county = County.query.get_or_404(id)
    db.session.delete(county)
    db.session.commit()
    return jsonify({'county': county.county_name + 'deleted successfully'})


@app.route('/v1/streets', methods=['GET'])
def get_streets():
    streets = Street.query.all()
    return jsonify({'streets': [street.to_json() for street in streets]})


@app.route('/v1/streets', methods=['POST'])
def post_streets():
    if not request.json or not 'street_name' in request.json or not 'county_id' in request.json:
        abort(400)
    street = Street(request.json['street_name'], request.json['county_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(street)
    db.session.commit()
    return jsonify({'street': street.street_name + ' created successfully'}), 201


@app.route('/v1/streets/<int:id>', methods=['GET'])
def get_street(id):
    street = Street.query.get_or_404(id)
    return jsonify(street.to_json)


@app.route('/v1/streets/<int:id>', methods=['PUT'])
def put_street(id):
    if not request.json:
        abort(400)
    street = Street.query.get_or_404(id)
    street.street_name = request.json.get('street_name', street.street_name)
    street.county_id = request.json.get('county_id', street.county_id)
    street.comments = request.json.get('comments', street.comments)
    db.session.commit()
    return jsonify({'street': 'updated successfully'})


@app.route('/v1/streets/<int:id>', methods=['DELETE'])
def delete_street(id):
    street = Street.query.get_or_404(id)
    db.session.delete(street)
    db.session.commit()
    return jsonify({'street': street.street_name + 'deleted successfully'})


@app.route('/v1/communities', methods=['GET'])
def get_communities():
    communities = Community.query.all()
    return jsonify({'communities': [community.to_json() for community in communities]})


@app.route('/v1/communities', methods=['POST'])
def post_communities():
    if not request.json or not 'community_name' in request.json or not 'street_id' in request.json:
        abort(400)
    community = Community(request.json['community_name'], request.json['street_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(community)
    db.session.commit()
    return jsonify({'community': community.community_name + ' created successfully'}), 201


@app.route('/v1/communities/<int:id>', methods=['GET'])
def get_community(id):
    community = Community.query.get_or_404(id)
    return jsonify(community.to_json)


@app.route('/v1/communities/<int:id>', methods=['PUT'])
def put_community(id):
    if not request.json:
        abort(400)
    community = Community.query.get_or_404(id)
    community.community_name = request.json.get('community_name', community.community_name)
    community.street_id = request.json.get('street_id', community.street_id)
    community.comments = request.json.get('comments', community.comments)
    db.session.commit()
    return jsonify({'community': 'updated successfully'})


@app.route('/v1/communities/<int:id>', methods=['DELETE'])
def delete_community(id):
    community = Community.query.get_or_404(id)
    db.session.delete(community)
    db.session.commit()
    return jsonify({'community': community.community_name + 'deleted successfully'})


@app.route('/v1/doors', methods=['GET'])
def get_doors():
    doors = Community.query.all()
    return jsonify({'doors': [door.to_json() for door in doors]})


@app.route('/v1/doors', methods=['POST'])
def post_doors():
    if not request.json or not 'door_name' in request.json or not 'serial_number' in request.json \
            or not 'hw_door_key' in request.json or not 'public_door' in request.json or not 'building' in \
            request.json or not 'unit' in request.json or not 'community_id' in request.json:
        abort(400)
    door = Door(request.json['door_name'], request.json['serial_number'], request.json['hw_door_key'], \
                request.json['public_door'], request.json['building'], request.json['unit'], \
                request.json['community_id'], 'superadmin', request.json.get('comments', ''))
    db.session.add(door)
    db.session.commit()
    return jsonify({'door': door.door_name + ' created successfully'}), 201


@app.route('/v1/doors/<int:id>', methods=['GET'])
def get_door(id):
    door = Door.query.get_or_404(id)
    return jsonify(door.to_json)


@app.route('/v1/door/<int:id>', methods=['PUT'])
def put_door(id):
    if not request.json:
        abort(400)
    door = Door.query.get_or_404(id)
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
def delete_door(id):
    door = Door.query.get_or_404(id)
    db.session.delete(door)
    db.session.commit()
    return jsonify({'door': door.door_name + 'deleted successfully'})


if __name__ == '__main__':
    app.run(debug=True)
