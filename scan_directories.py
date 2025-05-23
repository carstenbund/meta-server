import os
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm.exc import NoResultFound


# Database setup
DATABASE_URI = 'sqlite:///instance/files.db'

# Define the base class
class Base(DeclarativeBase):
    pass

#Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Define the DirectoryMetadata model
class DirectoryMetadata(Base):
    __tablename__ = 'directory_metadata'
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, unique=True, nullable=False)
    file_count = Column(Integer, nullable=False)
    total_size = Column(Integer, nullable=False)
    modification_date = Column(Float, nullable=False)

# Ensure database tables are created
Base.metadata.create_all(engine)

from sqlalchemy.orm.exc import NoResultFound

def scan_directories(directory):
    for subdir, _, files in os.walk(directory):
        # Check if the directory metadata already exists in the database
        try:
            existing_metadata = session.query(DirectoryMetadata).filter_by(path=subdir).one()
            print(f"Metadata for directory {subdir} already exists in the database.")
            continue  # Skip this directory if it already exists
        except NoResultFound:
            pass  # No existing record found, proceed to add new metadata

        file_count = len(files)
        total_size = sum(os.path.getsize(os.path.join(subdir, file)) for file in files)
        modification_date = os.path.getmtime(subdir)

        directory_metadata = DirectoryMetadata(
            path=subdir,
            file_count=file_count,
            total_size=total_size,
            modification_date=modification_date
        )
        session.add(directory_metadata)
        session.commit()
        print(f"Metadata for directory {subdir} added to database with {file_count} files.")

if __name__ == '__main__':
    directory_to_scan = '/win95/mcrlnsalg/'
    scan_directories(directory_to_scan)

