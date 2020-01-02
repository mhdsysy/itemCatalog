from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    categoryItems = relationship("Items", cascade="all, delete-orphan")

    @property
    def serialize(self):
        return {
            'Name': self.name,
            'Id': self.id,
            'items':
                [categoryItems.serialize for categoryItems in self.categoryItems]
            }


class Items(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    description = Column(String(250))
    date_added = Column(DateTime, nullable=False)

    picture = Column(String(250))


    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'description': self.description,
            'category': self.category.name

        }


engine = create_engine('sqlite:///database.db')

Base.metadata.create_all(engine)
