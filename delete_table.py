from sqlalchemy import create_engine, MetaData

DATABASE_URI = 'sqlite:///instance/files.db'
engine = create_engine(DATABASE_URI)
metadata = MetaData()

metadata.reflect(bind=engine)
file_metadata_table = metadata.tables.get('file_metadata')

if file_metadata_table is not None:
    file_metadata_table.drop(engine)
    print("Table dropped.")
else:
    print("Table does not exist.")

