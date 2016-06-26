#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, make_response, abort, json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from config import config


app = Flask(__name__)
app.config.from_object(config['default'])
db = SQLAlchemy(app)

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
    door_name = db.Column(db.String(32), unique=True)
    serial_number = db.Column(db.String(128), unique=True)
    hw_door_key = db.Column(db.String(128), unique=True)
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
        self.serial_number =serial_number
        self.hw_door_key = hw_door_key
        self.public_door = public_door
        self.building = building
        self.unit = unit
        self.community_id = community_id

    def cal_hw_door_key(self, hw_door_key=None):

        if hw_door_key is None:
            pass

    def to_json(self):
        json_door = {
            'id': self.id,
            'door_name': self.door_name,
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
    username = db.Column(db.String(64))
    password_hash = db.Column(db.String(128))
    real_name = db.Column(db.String(32))
    user_mobile = db.Column(db.String(16), unique=True)
    user_room = db.Column(db.String(32))
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)
    user_role = db.Column(db.String(16))
#    member_since = db.Column(db.Date)

    def to_json(self):
        json_user = {
            'id': self.id,
            'username': self.username,
            'real_name': self.real_name,
            'user_mobile': self.user_mobile,
            'user_room': self.user_room,
            'comments': self.comments,
            'user_role': self.user_role,
#            'member_since': self.member_since
        }
        return json_user

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

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


if __name__ == '__main__':
    app.run(debug=True)
