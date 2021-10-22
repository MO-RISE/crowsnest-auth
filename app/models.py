from sqlalchemy import Column, BigInteger, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.expression import null

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True, nullable=False, autoincrement=True)
    username = Column(String(255), index=True, nullable=False, unique=True)
    hashed_password = Column(String(255), nullable=False)
    path_whitelist = Column(ARRAY(String(255), dimensions=1))
    path_blacklist = Column(ARRAY(String(255), dimensions=1))
    topic_whitelist = Column(ARRAY(String(255), dimensions=1))
    topic_whitelist = Column(ARRAY(String(255), dimensions=1))
    tokens = Column(ARRAY)
