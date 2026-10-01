from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

Base = declarative_base()
engine = None
db_session = None

def init_db(database_uri):
    global engine, db_session
    if engine is not None:
        try:
            db_session.remove()
            engine.dispose()
        except Exception:
            pass

    # Normalize PostgreSQL connection URI for SQLAlchemy 2.0 compatibility
    if database_uri.startswith("postgres://"):
        database_uri = database_uri.replace("postgres://", "postgresql://", 1)

    connect_args = {}
    if "sqlite" in database_uri:
        connect_args = {"check_same_thread": False}
        
    engine = create_engine(
        database_uri,
        connect_args=connect_args,
        pool_pre_ping=True
    )
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
    Base.query = db_session.query_property()
    
    # Import models to ensure they are registered with Base metadata
    from database import models
    Base.metadata.create_all(bind=engine)
    return db_session

def get_db():
    global db_session
    return db_session

def close_db():
    global engine, db_session
    if db_session:
        try:
            db_session.remove()
        except Exception:
            pass
    if engine:
        try:
            engine.dispose()
        except Exception:
            pass
