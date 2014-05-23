# -*- coding: utf-8 -*-
'''
Copyright [2012]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------

This sets up sqlalchemy.
For more information about sqlalchemy check out http://www.sqlalchemy.org/

'''

from os import getcwd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.BaseObject import BaseObject

DBFILE_NAME = 'replicant.db'

metadata = BaseObject.metadata

# This is a relative path ///
engine = create_engine('sqlite:///' + DBFILE_NAME)
setattr(engine, 'echo', False)
Session = sessionmaker(bind=engine, autocommit=True)
dbsession = Session(autoflush=True)


# Import models (or the tables won't get created)
from models.User import User
from models.Job import Job
from models.PasswordHash import PasswordHash

# Calling this will create the tables at the database
create_tables = lambda: (setattr(engine, 'echo', True), metadata.create_all(engine))