# manage-postgres-user

AWS Lambda function to manage PostgreSQL users. This is a fork from from <https://github.com/dwp/manage-mysql-user> and adapted to communicate with a PostgreSQL database.

## Usage

The Lambda accepts the following keys in the payload JSON:

* `postgres_user_username` - (Required) PostgreSQL username whose password will be updated
* `postgres_database_name` - (Optional) PostgreSQL database name. Overrides the value set in the Environment variable
* `postgres_user_password_parameter_name` - (Optional, conflicts with `postgres_user_password_secret_name`) Name of SSM parameter that is used to store PostgreSQL user's password
* `postgres_user_password_secret_name` - (Optional, conflicts with `postgres_user_password_parameter_name`) Name of Secrets Manager secret that is used to store PostgreSQL user's password
* `privileges` - (Optional) If present, current privileges will be revoked and then granted as specified here. Accepts a comma-separated list of valid PostgreSQL privileges and optional table name after a colon. If a table name is specified for a privilege, it will be applied to the given table; otherwise to the whole database. Table name may only contain basic Latin letters, digits 0-9, at sign, hash, and an underscore. See examples below.

The following environment variables can be set:

* `RDS_DATABASE_NAME` - (Required) PostgreSQL database name. Can be overridden on an event level using the payload JSON
* `RDS_ENDPOINT` - (Required) DNS name where the database is reachable from
* `RDS_MASTER_PASSWORD_PARAMETER_NAME` - (Optional, conflicts with `RDS_MASTER_PASSWORD_SECRET_NAME`) Name of SSM parameter that is used to store PostgreSQL user's password
* `RDS_MASTER_PASSWORD_SECRET_NAME` - (Optional, conflicts with `RDS_MASTER_PASSWORD_PARAMETER_NAME`) Name of Secrets Manager secret that is used to store PostgreSQL user's password
* `RDS_MASTER_USERNAME` - (Required) PostgreSQL root username.

### Payload examples

Grants `ALL` on all tables.

```json
{
  "postgres_user_username": "foo",
  "postgres_user_password_secret_name": "bar",
  "privileges": "ALL"
}
```

Grants `ALL` on all tables in database `postgres` using SSM

```json
{
  "postgres_user_username": "foo",
  "postgres_database_name": "postgres",
  "postgres_user_password_secret_name": "bar",
  "postgres_user_password_parameter_name": "/parameter/path",
  "privileges": "ALL"
}
```

Grants `SELECT, CREATE, DROP` on all tables:

```json
{
  "postgres_user_username": "foo",
  "postgres_user_password_secret_name": "bar",
  "privileges": "SELECT, CREATE, DROP"
}
```

Grants `SELECT` on all tables, `UPDATE` on `table1` and `ALL` on `table2`:

```json
{
  "postgres_user_username": "foo",
  "postgres_user_password_secret_name": "bar",
  "privileges": "SELECT, UPDATE:table1, ALL:table2"
}
```

Grants `SELECT` on all tables, `UPDATE` and `INSERT` on `table1` and `ALL` on `table2`:

```json
{
  "postgres_user_username": "foo",
  "postgres_user_password_secret_name": "bar",
  "privileges": "SELECT, UPDATE:table1, INSERT:table1, ALL:table2"
}
```
