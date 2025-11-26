# models.py
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("THEWESCAN_DB", f"sqlite:///{os.path.join(BASE_DIR,'thewescan.db')}")

engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(512), nullable=False)
    profile = Column(String(64), default="default")
    status = Column(String(32), default="queued")
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    logs = Column(Text, default="")

    findings = relationship("Finding", back_populates="scanjob", cascade="all,delete-orphan")
    subdomains = relationship("Subdomain", back_populates="scanjob", cascade="all,delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scanjob_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    vuln_type = Column(String(64))
    url = Column(String(1024))
    param = Column(String(256), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    severity = Column(String(32), default="Medium")
    created_at = Column(DateTime, default=datetime.utcnow)

    scanjob = relationship("ScanJob", back_populates="findings")


class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(Integer, primary_key=True, index=True)
    scanjob_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    hostname = Column(String(512))
    ip = Column(String(64), nullable=True)
    status = Column(String(32), nullable=True)
    title = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scanjob = relationship("ScanJob", back_populates="subdomains")


def init_db():
    Base.metadata.create_all(bind=engine)
