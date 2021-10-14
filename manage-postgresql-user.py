#!/usr/bin/python
import logging
import os
import psycopg2
import boto3
import random
import string
import json
from datetime import datetime

libraries = ("boto3", "psycopg2")

# Initialise logging
logger = logging.getLogger(__name__)
log_level = os.environ["LOG_LEVEL"] if "LOG_LEVEL" in os.environ else "INFO"
logger.setLevel(logging.getLevelName(log_level.upper()))
logger.info("Logging at {} level".format(log_level.upper()))

# Use appropriate CA SSL cert to verify RDS identity. Use "AmazonRootCA1.pem" for Aurora Serverless.
# Defaults to "rds-ca-2019-2015-root.pem" to suit normal RDS.
rds_ca_cert = (
    os.environ["RDS_CA_CERT"]
    if "RDS_CA_CERT" in os.environ
    else "/var/task/rds-ca-2019-2015-root.pem"
)


def generate_password():
    """Generate a password.

    Args:
        None

    Returns:
        str: generated password
    """
    valid_chars = string.ascii_letters + string.digits + string.punctuation
    invalid_chars = [
        "/",
        "@",
        '"',
        "\\",
        "'",
        "_",
        "$",
    ]  # Not allowed in a PostgreSQL password
    pw_chars = "".join([i for i in valid_chars if i not in invalid_chars])
    pw = "".join((random.choice(pw_chars)) for x in range(40))
    logger.debug("Password generated")
    return pw


def update_password_source(username, password, password_source, password_source_type):
    """Update password stored in AWS SSM or Secrets Manager

    Args:
        username (str): username

        password (str): password

        password_source (str): name of entity storing the password
                               e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"
    Returns:
        None
    """
    if password_source_type == "ssm":
        ssm = boto3.client("ssm")
        try:
            ssm.put_parameter(
                Name=password_source,
                Type="SecureString",
                Value=password,
                Overwrite=True,
            )
            logger.debug(f"Password updated in {password_source_type}")
        except Exception as e:
            logger.error(e)
            raise e
    elif password_source_type == "secretsmanager":
        secretsmanager = boto3.client("secretsmanager")
        try:
            # Engine and port are hard-coded as these parameters can only be used with Aurora Serverless
            secret_value = {
                "dbInstanceIdentifier": os.environ["RDS_DATABASE_NAME"],
                "engine": "aurora-postgresql",
                "host": os.environ["RDS_ENDPOINT"],
                "port": 5432,
                "username": username,
                "password": password,
            }
            secretsmanager.put_secret_value(
                SecretId=password_source, SecretString=json.dumps(secret_value)
            )
            secretsmanager.tag_resource(
                SecretId=password_source,
                Tags=[
                    {"Key": "LastRotated", "Value": str(datetime.now())},
                ],
            )
            logger.debug(f"Password updated in {password_source_type}")
        except Exception as e:
            logger.error(e)
            raise e
    else:
        raise Exception(f"Unknown password source type: {password_source_type}")


def get_postgres_password(password_source, password_source_type):
    """Return password stored in AWS SSM or Secrets Manager

    Args:
        password_source (str): name of entity storing the password
                               e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"
    Returns:
        str: retrieved password
    """
    if password_source_type == "ssm":
        ssm = boto3.client("ssm")
        return ssm.get_parameter(Name=password_source, WithDecryption=True)[
            "Parameter"
        ]["Value"]
    elif password_source_type == "secretsmanager":
        secretsmanager = boto3.client("secretsmanager")
        secret_string_json = json.loads(
            secretsmanager.get_secret_value(SecretId=password_source)["SecretString"]
        )
        password = secret_string_json["password"]
        return password
    else:
        raise Exception(f"Unknown password source type: {password_source_type}")


def get_connection(username, password):
    """Return PostgreSQL connection

    Args:
        username (str): PostgreSQL username

        password (str): PostgreSQL password

    Returns:
        obj: PostgreSQL connection
    """
    return psycopg2.connect(
        host=os.environ["RDS_ENDPOINT"],
        user=username,
        password=password,
        port=5432,
        database=os.environ["RDS_DATABASE_NAME"],
        sslmode="require",
        sslrootcert="rds-ca-2019-2015-root.pem",
    )


def execute_statement(sql, username, password_source, password_source_type):
    """Execute PostgreSQL statement that does not return data

    Args:
        sql (str): PostgreSQL statement

        username (str): PostgreSQL username

        password_source (str): name of entity storing the password for the
                               username, e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"

    Returns:
        None
    """
    connection = get_connection(
        username, get_postgres_password(password_source, password_source_type)
    )
    logger = logging.getLogger()
    cursor = connection.cursor()
    cursor.execute(sql)
    connection.commit()
    cursor.close()
    connection.close()


def execute_query(sql, username, password_source, password_source_type):
    """Execute PostgreSQL statement that returns data

    Args:
        sql (str): PostgreSQL statement

        username (str): PostgreSQL username used to login into server

        password_source (str): name of entity storing the password for the
                               username, e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"

    Returns:
         PostgreSQL rows as a list of tuples.
    """
    connection = get_connection(
        username, get_postgres_password(password_source, password_source_type)
    )
    logger = logging.getLogger()
    cursor = connection.cursor()
    cursor.execute(sql)
    result = cursor.fetchall()
    connection.commit()
    connection.close()
    return result


def check_user_exists(master_username, username, password_source, password_source_type):
    """Check if a user <username> exists in PostgreSQL server

    Args:
        master_username (str): PostgreSQL master username. This is used to login.

        username (str): PostgreSQL username existence of which is to be checked.

        password_source (str): name of entity storing the password for the
                               master username, e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"

    Returns:
         Boolean: True if user exists, False otherwise
    """

    result = execute_query(
        "SELECT rolname FROM pg_roles WHERE rolname = '{}';".format(username),
        master_username,
        password_source,
        password_source_type,
    )
    if len(result) > 0:
        if username in result[0]:
            logger.debug(f"User {username} found in database: {result}")
            return True
        else:
            logger.error(
                f"Unexpected query result while checking if user {username} exists in database: {result}"
            )
    else:
        logger.debug(f"User {username} doesn't exist in database")
        return False


def test_connection(username, password_source, password_source_type):
    """Check if a user <username> can login into PostgreSQL server

    Args:
        username (str): PostgreSQL username

        password_source (str): name of entity storing the password for the
                               username, e.g. SSM parameter name or
                               Secrets Manager secret name

        password_source_type (str): type of entity storing the password.
                                    Accepts one of two values:
                                        "secretsmanager"
                                        "ssm"

    Returns:
         Boolean: True if login successful, False otherwise
    """
    postgres_user_password = get_postgres_password(
        password_source, password_source_type
    )
    try:
        connection = psycopg2.connect(
            host=os.environ["RDS_ENDPOINT"],
            user=username,
            password=postgres_user_password,
            port=5432,
            database=os.environ["RDS_DATABASE_NAME"],
            sslmode="require",
            sslrootcert="rds-ca-2019-2015-root.pem",
        )
    except Exception as e:
        logger.error(e)
        return False
    else:
        return True


def validate_event(event):
    """Validate event JSON received as input

    Args:
        event (dict): JSON received as input

    Returns:
        None

    Raises:
        ValueError: Invalid event
    """
    valid_privileges = [
        "ALL",
        "CREATE",
        "CONNECT" "DELETE",
        "EXECUTE",
        "INSERT",
        "REFERENCES",
        "SELECT",
        "TEMPORARY",
        "TRIGGER",
        "TRUNCATE",
        "UPDATE",
        "USAGE",
    ]
    valid_chars_in_table_name = string.ascii_letters + string.digits + "@" + "_" + "#"
    privilege_err_msg = """
    Invalid event: 'privileges' must contain a comma-separated list of valid PostgreSQL privileges 
    with optional table names after a colon, e.g.
    "SELECT, UPDATE:table1, ALL:table2"
    Table name may only contain basic Latin letters, digits 0-9, at, underscore, hash
    """

    is_valid = True

    if "postgres_user_username" not in event.keys():
        logger.error(f"Invalid event: 'postgres_user_username' must be set")
        is_valid = False

    # Check that one of these keys is present but not both at the same time
    if ("postgres_user_password_parameter_name" in event.keys()) is (
        "postgres_user_password_secret_name" in event.keys()
    ):
        logger.error(
            f"Invalid event: One and only one of 'postgres_user_password_parameter_name', 'postgres_user_password_secret_name' must be set"
        )
        is_valid = False

    if "privileges" in event.keys():
        for privilege_table in event["privileges"].split(", "):
            privilege = privilege_table.split(":")[0]
            if privilege not in valid_privileges:
                logger.error(privilege_err_msg)
                is_valid = False

            if len(privilege_table.split(":")) not in [1, 2]:
                logger.error(privilege_err_msg)
                is_valid = False

            if len(privilege_table.split(":")) == 2:
                table = privilege_table.split(":")[1]
                for i in table:
                    if i not in valid_chars_in_table_name:
                        logger.error(privilege_err_msg)
                        is_valid = False

    if not is_valid:
        raise ValueError("Invalid event")


def validate_envvars():
    """Validate configuration supplied in environment variables

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: Invalid environment variable value(s)
    """
    is_valid = True

    if not "RDS_ENDPOINT" in os.environ:
        logger.error(f"Invalid environment variable value: 'RDS_ENDPOINT' must be set")
        is_valid = False

    if not "RDS_DATABASE_NAME" in os.environ:
        logger.error(
            f"Invalid environment variable value: 'RDS_DATABASE_NAME' must be set"
        )
        is_valid = False

    if not "RDS_MASTER_USERNAME" in os.environ:
        logger.error(
            f"Invalid environment variable value: 'RDS_MASTER_USERNAME' must be set"
        )
        is_valid = False

    # Check that one of these vars is present but not both at the same time
    if ("RDS_MASTER_PASSWORD_SECRET_NAME" in os.environ) is (
        "RDS_MASTER_PASSWORD_PARAMETER_NAME" in os.environ
    ):
        logger.error(
            f"Invalid environment variable values: One and only one of 'RDS_MASTER_PASSWORD_SECRET_NAME', 'RDS_MASTER_PASSWORD_PARAMETER_NAME' must be set"
        )
        is_valid = False

    if not is_valid:
        raise ValueError("Invalid environment variable value(s)")


def handler(event, context):

    logger.info(f"Event: {event}")

    validate_event(event)
    validate_envvars()

    if "postgres_user_password_secret_name" in event.keys():
        postgres_user_password_source = event["postgres_user_password_secret_name"]
        postgres_user_password_source_type = "secretsmanager"
    else:
        postgres_user_password_source = event["postgres_user_password_parameter_name"]
        postgres_user_password_source_type = "ssm"

    if "RDS_MASTER_PASSWORD_SECRET_NAME" in os.environ:
        postgres_master_password_source = os.environ["RDS_MASTER_PASSWORD_SECRET_NAME"]
        postgres_master_password_source_type = "secretsmanager"
    else:
        postgres_master_password_source = os.environ[
            "RDS_MASTER_PASSWORD_PARAMETER_NAME"
        ]
        postgres_master_password_source_type = "ssm"

    postgres_user_username = event["postgres_user_username"]
    postgres_master_username = os.environ["RDS_MASTER_USERNAME"]
    database = os.environ["RDS_DATABASE_NAME"]

    logger.info(f"Updating {postgres_user_username}")
    pw = generate_password()
    update_password_source(
        postgres_user_username,
        pw,
        postgres_user_password_source,
        postgres_user_password_source_type,
    )
    user_exists = check_user_exists(
        postgres_master_username,
        postgres_user_username,
        postgres_master_password_source,
        postgres_master_password_source_type,
    )
    if user_exists:
        logger.info(
            f"User {postgres_user_username} already exists in PostgreSQL, will update password"
        )
    else:
        logger.info(
            f"User {postgres_user_username} doesn't exist in PostgreSQL and will be created"
        )

    # In Aurora CREATE USER IF NOT EXISTS does not update password for existing user, hence SET PASSWORD is required
    execute_statement(
        """
        DO
        $do$
        BEGIN
        IF NOT EXISTS (
            SELECT FROM pg_catalog.pg_roles
            WHERE rolname = '{}'
        )
        THEN
            CREATE ROLE {} LOGIN PASSWORD '{}';
        END IF;
        END
        $do$;
        """.format(
            postgres_user_username, postgres_user_username, pw
        ),
        postgres_master_username,
        postgres_master_password_source,
        postgres_master_password_source_type,
    )
    execute_statement(
        "ALTER USER {} WITH PASSWORD '{}';".format(postgres_user_username, pw),
        postgres_master_username,
        postgres_master_password_source,
        postgres_master_password_source_type,
    )

    if "privileges" in event.keys():
        if len(event["privileges"]) > 0:
            privileges = event["privileges"]
            logger.info(
                f"Revoking existing privileges and granting {privileges} to PostgreSQL user {postgres_user_username}"
            )
            # Revoke all privilegest first
            execute_statement(
                "REVOKE ALL ON DATABASE {} FROM {};".format(
                    database,
                    postgres_user_username,
                ),
                postgres_master_username,
                postgres_master_password_source,
                postgres_master_password_source_type,
            )
            # Grant those priviledges needed
            execute_statement(
                "GRANT ALL ON DATABASE {} TO {};".format(
                    database, postgres_user_username
                ),
                postgres_master_username,
                postgres_master_password_source,
                postgres_master_password_source_type,
            )
            for privilege_table in event["privileges"].split(", "):
                privilege = privilege_table.split(":")[0]
                table = (
                    "TABLE " + privilege_table.split(":")[1]
                    if len(privilege_table.split(":")) == 2
                    else "ALL TABLES IN SCHEMA public"
                )
                execute_statement(
                    "GRANT {} ON {} TO {};".format(
                        privilege, table, postgres_user_username
                    ),
                    postgres_master_username,
                    postgres_master_password_source,
                    postgres_master_password_source_type,
                )
    else:
        logger.info(
            f"Privileges not changed for PostgreSQL user {postgres_user_username} as 'privileges' key not set in payload"
        )

    test_result = test_connection(
        postgres_user_username,
        postgres_user_password_source,
        postgres_user_password_source_type,
    )
    if test_result:
        logger.info(
            f"Password rotation complete: PostgreSQL user {postgres_user_username} succesfully logged in using password from source {postgres_user_password_source} in {postgres_user_password_source_type}"
        )
    else:
        raise ValueError(
            f"Password rotation failed: PostgreSQL user {postgres_user_username} failed to login using password from source {postgres_user_password_source} in {postgres_user_password_source_type}"
        )


if __name__ == "__main__":
    script_dir = os.path.dirname(__file__)
    rel_path = "../resources"
    abs_file_path = os.path.join(script_dir, rel_path)

    with open(os.path.join(abs_file_path, "event.json"), "r") as file:
        json_content = json.loads(file.read())
        handler(json_content, None)
