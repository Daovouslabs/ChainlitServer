import os

from chainlit.config import PACKAGE_ROOT, config, APP_ROOT
from chainlit.logger import logger

SCHEMA_PATH = os.path.join(PACKAGE_ROOT, "db/prisma/schema.prisma")
CUSTOM_SCHEMA_PATH = os.path.join(APP_ROOT, "configs/schemas/schema.prisma")

def db_push():
    from importlib import reload

    import prisma
    from prisma.cli.prisma import run

    if config.project.database == "local":
        args = ["db", "push", f"--schema={SCHEMA_PATH}"]
        env = {"LOCAL_DB_PATH": os.environ.get("LOCAL_DB_PATH")}
    elif config.project.database == "custom":
        args = ["db", "push", f"--schema={CUSTOM_SCHEMA_PATH}"]
        env = {"DATABASE_URL": os.environ.get("DATABASE_URL")}
    run(args, env=env)
    # Without this the client will fail to initialize the first time.
    reload(prisma)


def init_local_db():
    if config.project.database == "local":
        if not os.path.exists(config.project.local_db_path):
            db_push()
    elif config.project.database == "custom":
        db_push()


def migrate_local_db():
    if config.project.database == "local":
        if os.path.exists(config.project.local_db_path):
            db_push()
            logger.info(f"Local db migrated")
    elif config.project.database == "custom":
        db_push()
        logger.info(f"Custom db migrated")
    else:
        logger.info(f"Local or custom db does not exist, skipping migration")
