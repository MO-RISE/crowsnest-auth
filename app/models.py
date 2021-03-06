"""SQLAlchemy ORM models"""

from sqlalchemy import Column, BigInteger, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.declarative import declarative_base
from databases.backends.postgres import Record

Base = declarative_base()


class User(Base):  # pylint: disable=missing-class-docstring,too-few-public-methods
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True, nullable=False, autoincrement=True)
    username = Column(String(255), index=True, nullable=False, unique=True)
    hashed_password = Column(String(255), nullable=False)
    path_whitelist = Column(ARRAY(String(255), dimensions=1))
    path_blacklist = Column(ARRAY(String(255), dimensions=1))
    topic_whitelist = Column(ARRAY(String(255), dimensions=1))
    topic_blacklist = Column(ARRAY(String(255), dimensions=1))
    token = Column(String(255))

    @classmethod
    def from_record(cls, record: Record):
        """Create a User instance from a asyncpg record

        Args:
            record (Record): AsyncPG record

        Returns:
            User: User instance
        """
        return cls(**dict(record))


users = User.__table__
