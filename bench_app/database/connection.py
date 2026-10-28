from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

from bench_app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100))
    is_active = Column(Boolean, default=True)


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    price = Column(Integer)
    category = Column(String(50))


def init_db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    if session.query(User).count() == 0:
        session.add(User(username="alice", email="alice@example.com", is_active=True))
        session.add(User(username="bob", email="bob@example.com", is_active=True))
        session.add(Product(name="Widget A", price=100, category="gadgets"))
        session.add(Product(name="Gadget B", price=250, category="gadgets"))
        session.commit()
    session.close()
