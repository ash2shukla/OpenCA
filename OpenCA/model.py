from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from os import path

Base = declarative_base()

class Index(Base):
	__tablename__ = "index"
	id = Column(Integer,primary_key=True)
	status_flag = Column(String(1), default='V')
	expiration_date = Column(String(20))
	revocation_date = Column(String(20), default= '')
	revocation_reason = Column(String(1000), default='')
	serial_number_in_hex = Column(String(10))
	cert_filename = Column(String(50), default='unknown')
	cert_subject = Column(String(500))

def getDB(_path):
	engine = create_engine('sqlite:///'+path.join(path.abspath(_path),'index.db'))
	Base.metadata.create_all(engine)
	return engine
