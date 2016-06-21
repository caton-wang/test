#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
#basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'something weird to guess'
    SSL_DISABLE =False
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    FLASKY_MAIL_SUBJECT_PREFIX = '[GateSystem]'
    FLASKY_MAIL_SENDER = 'GateSystem Admin <noreply@example.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')


class DevConfig(Config):
    DEBUG = True
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
    #    'sqlite:///' + os.path.join(basedir, 'dev.sqlite')

    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'mysql://root:password@localhost/dev?charset=utf8'



class ProdConfig(Config):
    #SQLALCHEMY_DATABASE_URI = os.environ.get('PROD_DATABASE_URL') or \
    #    'sqlite:///' + os.path.join(basedir, 'prod.sqlite')

    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'mysql://root:password@localhost/prod'


config = {
    'dev': DevConfig,
    'prod': ProdConfig,
    'default': DevConfig
}