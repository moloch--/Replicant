# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, or_
from sqlalchemy.orm import relationship, backref
from sqlalchemy.types import String
from models.BaseObject import BaseObject


class PasswordHash(BaseObject):

    digest = Column(String(32), nullable=False)
    username = Column(String(32))
    preimage = Column(String(32))

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    def is_cracked(self):
        return preimage is not None