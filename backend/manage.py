from app import create_app, db
from app.models import User # Make sure to import your models

# Create an app instance
app = create_app()

# The 'app_context' is needed for SQLAlchemy to know which app it's working with
with app.app_context():
    print("Creating all database tables...")
    db.create_all()
    print("Done!")