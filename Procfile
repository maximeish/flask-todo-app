web: gunicorn wsgi:app
release: python manage.py create_db
release: python manage.py db init
release: python manage.py db migrate
