from models import app, db
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
import os


migrate = Migrate(app, db)
manager = Manager(app)

# migrations
manager.add_command('db', MigrateCommand)


@manager.command
def create_db():
    """Creates the db tables."""
    db.create_all()
    os.system('python manage.py db init')
    os.system('python manage.py db migrate')


@manager.command
def drop_db():
    """Drops the db tables."""
    db.drop_all()


if __name__ == '__main__':
    manager.run()
