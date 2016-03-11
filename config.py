import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECURET_KEY = os.environ.get('SECURET_KEY') or '\xb1\xdd\x9b\xbbG\x90\xa5\xfb\x11\x8ai\xca\xd6\xf3!3DO\xbcG@\xf2\x8e\x84'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKR_ADMIN = os.environ.get('FLASKR_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = '587'
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SQLALCHEMY_DATABASE_URL = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = False
    SQLALCHEMY_DATABASE_URL = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URL = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
