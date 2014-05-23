# -*- coding: utf-8 -*-
'''
Created on Mar 12, 2012

@author: moloch
'''


from models import dbsession
from sqlalchemy import Column, or_
from sqlalchemy.orm import relationship, backref
from sqlalchemy.types import String, Boolean
from models.BaseObject import BaseObject


class Job(BaseObject):

    user_id = Column()
    name = Column(String(32), nullable=False)
    algorithm = Column(String(32), nullable=False)
    hashes = relationship("PasswordHash",
        backref=backref("Job", lazy="select"),
        cascade="all, delete-orphan"
    )
    is_completed = Column(Boolean, defalut=False)

    @classmethod
    def by_id(cls, sid):
        return dbsession.query(cls).filter_by(id=sid).first()

    @classmethod
    def by_uuid(cls, juuid):
        return dbsession.query(cls).filter_by(uuid=juuid).first()

    def __len__(self):
        return len(self.hashes)