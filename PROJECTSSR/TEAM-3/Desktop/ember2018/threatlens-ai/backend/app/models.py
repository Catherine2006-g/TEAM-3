from sqlalchemy import (
    BigInteger,
    Boolean,
    CHAR,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False, server_default=text("'user'"))
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    files = relationship("File", back_populates="user")


class File(Base):
    __tablename__ = "files"

    file_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.user_id"),
        nullable=False
    )
    filename = Column(String, nullable=False)
    file_hash = Column(String, nullable=False)
    file_size = Column(BigInteger, nullable=False)
    file_type = Column(String, nullable=True)
    upload_time = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )
    status = Column(
        String,
        server_default=text("'Pending Analysis'")
    )

    user = relationship("User", back_populates="files")

    static_analysis = relationship(
        "StaticAnalysis",
        back_populates="file",
        uselist=False
    )

    reports = relationship(
        "Report",
        back_populates="file"
    )


class StaticAnalysis(Base):
    __tablename__ = "static_analysis"

    analysis_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    file_id = Column(
        Integer,
        ForeignKey("files.file_id"),
        nullable=False
    )

    md5_hash = Column(CHAR(32), nullable=True)
    sha256_hash = Column(CHAR(64), nullable=True)
    file_entropy = Column(Numeric, nullable=True)

    pe_features = Column(JSONB, nullable=True)
    imports = Column(JSONB, nullable=True)
    exports = Column(JSONB, nullable=True)
    strings = Column(Text, nullable=True)
    urls = Column(JSONB, nullable=True)

    # Python attribute: file_metadata
    # PostgreSQL column: metadata
    file_metadata = Column(
        "metadata",
        JSONB,
        nullable=True
    )

    risk_score = Column(Numeric, nullable=True)

    created_at = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    file = relationship(
        "File",
        back_populates="static_analysis"
    )

    ember_features = relationship(
        "EmberFeatures",
        back_populates="analysis",
        uselist=False
    )


class EmberFeatures(Base):
    __tablename__ = "ember_features"

    feature_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    analysis_id = Column(
        Integer,
        ForeignKey("static_analysis.analysis_id"),
        nullable=False
    )

    byte_features = Column(JSONB, nullable=True)
    histogram_features = Column(JSONB, nullable=True)
    string_features = Column(JSONB, nullable=True)
    general_features = Column(JSONB, nullable=True)
    header_features = Column(JSONB, nullable=True)
    section_features = Column(JSONB, nullable=True)
    import_features = Column(JSONB, nullable=True)
    export_features = Column(JSONB, nullable=True)

    created_at = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    analysis = relationship(
        "StaticAnalysis",
        back_populates="ember_features"
    )

    prediction = relationship(
        "Prediction",
        back_populates="feature",
        uselist=False
    )


class Prediction(Base):
    __tablename__ = "predictions"

    prediction_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    feature_id = Column(
        Integer,
        ForeignKey("ember_features.feature_id"),
        nullable=False
    )

    model_name = Column(String, nullable=False)
    malware_family = Column(String, nullable=True)
    prediction_label = Column(String, nullable=False)
    confidence = Column(Numeric, nullable=True)

    prediction_time = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    feature = relationship(
        "EmberFeatures",
        back_populates="prediction"
    )

    threat_logs = relationship(
        "ThreatLog",
        back_populates="prediction"
    )


class ThreatLog(Base):
    __tablename__ = "threat_logs"

    log_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    prediction_id = Column(
        Integer,
        ForeignKey("predictions.prediction_id"),
        nullable=False
    )

    severity = Column(String, nullable=False)

    status = Column(
        String,
        server_default=text("'Detected'")
    )

    description = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    prediction = relationship(
        "Prediction",
        back_populates="threat_logs"
    )

    alerts = relationship(
        "Alert",
        back_populates="threat_log"
    )


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    log_id = Column(
        Integer,
        ForeignKey("threat_logs.log_id"),
        nullable=False
    )

    message = Column(Text, nullable=False)

    is_read = Column(
        Boolean,
        server_default=text("false")
    )

    created_at = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    threat_log = relationship(
        "ThreatLog",
        back_populates="alerts"
    )


class Report(Base):
    __tablename__ = "reports"

    report_id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    file_id = Column(
        Integer,
        ForeignKey("files.file_id"),
        nullable=False
    )

    report_path = Column(String, nullable=False)

    generated_at = Column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP")
    )

    file = relationship(
        "File",
        back_populates="reports"
    )