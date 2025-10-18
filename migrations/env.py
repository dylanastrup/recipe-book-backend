import logging
from logging.config import fileConfig

# We import our app and db instances directly. This is the key change.
from app import app
from models import db

from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')


# --- START OF MODIFICATIONS ---

# This forces alembic to use the database URL from our app's configuration.
# This is what makes it connect to PostgreSQL on Render instead of a default SQLite.
config.set_main_option('sqlalchemy.url', str(app.config.get('SQLALCHEMY_DATABASE_URI')))

# We set the target metadata directly from our imported db object from models.py
target_metadata = db.metadata

# --- END OF MODIFICATIONS ---


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.
    ...
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.
    ...
    """
    # Create an engine from our app's configuration to connect to the database
    connectable = engine_from_config(
        config.get_section(config.config_main_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()