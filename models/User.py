# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, or_
from sqlalchemy.orm import relationship, backref
from sqlalchemy.types import String, DateTime
from models.BaseObject import BaseObject
from pbkdf2 import PBKDF2
from datetime import datetime

### Constants
ITERATE = 0xbad


class User(BaseObject):

    nick = Column(String(32), unique=True, nullable=False)
    last_login = Column(DateTime, default=datetime.now)
    _history = relationship("Job",
        backref=backref("User", lazy="select"),
        cascade="all, delete-orphan"
    )
    _password = Column('password', String(64))
    password = synonym('_password', descriptor=property(
        lambda self: self._password,
        lambda self, password: setattr(
                self, '_password', self.__class__._hash_password(password))
    ))

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @classmethod
    def by_nick(cls, nick):
        return dbsession.query(cls).filter_by(nick=nick).first()

    @classmethod
    def _hash_password(cls, password):
        return PBKDF2.crypt(password, iterations=ITERATE)

    def validate_password(self, attempt):
        ''' Check the password against existing credentials '''
        if self._password is not None:
            return self.password == PBKDF2.crypt(attempt, self.password)
        else:
            return False

    def __str__(self):
        return self.nick
