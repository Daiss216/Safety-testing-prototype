from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey
from database import Base


class Test(Base):
    __tablename__ = "tests"
    id = Column(String, primary_key=True)
    name = Column(String)
    status = Column(String, default="open")          # open | concluded
    created_at = Column(Float)
    genesis_hash = Column(String)


class Payload(Base):
    __tablename__ = "payloads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(String, ForeignKey("tests.id"))
    team = Column(String)                            # red | blue
    ciphertext = Column(Text)                        # Fernet, per-test key


class Ledger(Base):
    __tablename__ = "ledger"
    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(String, ForeignKey("tests.id"))
    prev_hash = Column(String)
    hash = Column(String)                            # SHA-256 of record body
    event_type = Column(String)
    data = Column(Text)                              # canonical JSON body
    signature = Column(String)                       # HMAC-SHA256
    ts = Column(Float)                               # unix timestamp