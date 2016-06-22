#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, json
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import Api, Resource, reqparse, fields, marshal
from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from config import config


app = Flask(__name__)
app.config.from_object(config['default'])
db = SQLAlchemy(app)
api = Api(app)

# database section


class Province(db.Model):
    __tablename__ = 'provinces'
    id = db.Column(db.Integer, primary_key=True)
    province_name = db.Column(db.String(32), unique=True)
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

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

    def to_json(self):
        json_county = {
            'id': self.id,
            'county_name': self.county_name,
            'city_id': self.city_id,
            'comments': self.comments
        }

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

    def to_json(self):
        json_street = {
            'id': self.id,
            'street_name': self.street_name,
            'county_id': self.county_id,
            'comments': self.comments
        }

    def __repr__(self):
        return self.street_name


class Community(db.Model):
    __tablename__ = 'communities'
    id = db.Column(db.Integer, primary_key=True)
    community_name = db.Column(db.Integer, unique=True)
    street_id = db.Column(db.Integer, db.ForeignKey('streets.id'))
    street = db.relationship('Street',backref=db.backref('communities', lazy='dynamic') )
    created_by_admin = db.Column(db.String(16))
    comments = db.Column(db.Text)

    def to_json(self):
        json_community = {
            'id': self.id,
            'community_name': self.community_name,
            'street_id': self.street_id,
            'comments': self.comments,
        }

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
    member_since = db.Column(db.Date)

    def to_json(self):
        json_user = {
            'id': self.id,
            'username': self.username,
            'real_name': self.real_name,
            'user_mobile': self.user_mobile,
            'user_room': self.user_room,
            'comments': self.comments,
            'user_role': self.user_role,
            'member_since': self.member_since
        }

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

province_fields = {
    'province_name': fields.String,
    'comments': fields.String,
    'uri': fields.Url('provinces')
}


class ProvincesAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('province_name', type=str, required=True, help='No province name provided',
                                   location='json')
        self.reqparse.add_argument('comments', type=str, default="", location='json')
        super(ProvincesAPI, self).__init__()

    def get(self):
        provinces = Province.query.all()
        return jsonify({'provinces': [province.to_json() for province in provinces]})

    def post(self):
        pass

api.add_resource(ProvincesAPI, '/v1/provinces', endpoint='provinces')


class ProvinceAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('province_name', type=str, location='json')
        self.reqparse.add_argument('comments', type=str, location='json')
        super(ProvinceAPI, self).__init__()

    def get(self, id):
        province = Province.query.get_or_404(id)
        return jsonify(province.to_json())

    def put(self, id):
        pass

    def delete(self, id):
        pass

api.add_resource(ProvinceAPI, '/v1/provinces/<int:id>', endpoint='province')


class CitiesAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('city_name', type=str, required=True, help='No city name provided',
                                   location='json')
        self.reqparse.add_argument('comments', type=str, default="", location='json')
        super(CitiesAPI, self).__init__()

    def get(self):
        cities = City.query.all()
        return jsonify({'cities': [city.to_json() for city in cities]})

    def post(self):
        pass

api.add_resource(CitiesAPI, '/v1/cities', endpoint='cities')


class CityAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('city_name', type=str, location='json')
        self.reqparse.add_argument('province_id', type=int, location='json')
        self.reqparse.add_argument('comments', type=str, location='json')
        super(CityAPI, self).__init__()

    def get(self, id):
        city = City.query.get_or_404(id)
        return jsonify(city.to_json())

    def put(self, id):
        pass

    def delete(self, id):
        pass

api.add_resource(CityAPI, '/v1/cities/<int:id>', endpoint='city')


class CountiesAPI(Resource):
    def get(self):
        counties = County.query.all()
        return jsonify({'counties': [county.to_json() for county in counties]})

    def post(self):
        pass

api.add_resource(CountiesAPI, '/v1/counties', endpoint='counties')


class CountyAPI(Resource):
    def get(self, id):
        county = County.query.get_or_404(id)
        return jsonify(county.to_json())

    def put(self):
        pass

    def delete(self):
        pass

api.add_resource(CountyAPI, '/v1/counties/<int:id>', endpoint='county')

if __name__ == '__main__':
    app.run(debug=True)
