-- App-shaped tables for `horus state` (sqlserver connector), mirroring postgres-shop.sql:
-- orders = stale, sync_jobs = active with failures, audit_exports = legacy.
IF DB_ID('shop') IS NULL CREATE DATABASE shop;
GO
USE shop;
GO
DROP TABLE IF EXISTS dbo.orders, dbo.sync_jobs, dbo.audit_exports;
GO
CREATE TABLE dbo.orders (
  id int IDENTITY PRIMARY KEY,
  customer nvarchar(50) NOT NULL,
  status nvarchar(30) NOT NULL,
  total decimal(10,2) NOT NULL,
  created_at datetime2 NOT NULL,
  updated_at datetimeoffset NOT NULL
);
CREATE TABLE dbo.sync_jobs (
  id int IDENTITY PRIMARY KEY,
  job_name nvarchar(50) NOT NULL,
  last_run_status nvarchar(30) NOT NULL,
  last_run_started_at datetime2 NOT NULL,
  error nvarchar(200) NULL
);
CREATE TABLE dbo.audit_exports (
  id int IDENTITY PRIMARY KEY,
  state nvarchar(30) NOT NULL,
  date date NOT NULL
);
GO
DECLARE @g int = 1;
WHILE @g <= 120
BEGIN
  INSERT INTO dbo.orders (customer, status, total, created_at, updated_at) VALUES (
    CONCAT('cust-', @g),
    CASE WHEN @g % 10 = 0 THEN 'payment_failed' WHEN @g % 7 = 0 THEN 'pending' ELSE 'completed' END,
    @g * 3.5,
    DATEADD(hour, -@g, DATEADD(day, -3, SYSUTCDATETIME())),
    DATEADD(minute, -@g, DATEADD(day, -3, SYSDATETIMEOFFSET())));
  SET @g += 1;
END;
SET @g = 1;
WHILE @g <= 30
BEGIN
  INSERT INTO dbo.sync_jobs (job_name, last_run_status, last_run_started_at, error) VALUES (
    CONCAT('sync-', @g),
    CASE WHEN @g % 4 = 0 THEN 'failed' WHEN @g % 5 = 0 THEN 'retrying' ELSE 'succeeded' END,
    DATEADD(minute, -7 * @g, SYSUTCDATETIME()),
    CASE WHEN @g % 4 = 0 THEN 'upstream 502 from inventory API' END);
  SET @g += 1;
END;
SET @g = 1;
WHILE @g <= 12
BEGIN
  INSERT INTO dbo.audit_exports (state, date) VALUES (
    CASE WHEN @g % 3 = 0 THEN 'cancelled' ELSE 'exported' END,
    CAST(DATEADD(day, -200 - @g, SYSUTCDATETIME()) AS date));
  SET @g += 1;
END;
GO
-- Read-only login, as the connector docs recommend.
IF SUSER_ID('horus_ro') IS NULL CREATE LOGIN horus_ro WITH PASSWORD = 'Horus-local-Pass1', CHECK_POLICY = OFF;
GO
IF USER_ID('horus_ro') IS NULL CREATE USER horus_ro FOR LOGIN horus_ro;
ALTER ROLE db_datareader ADD MEMBER horus_ro;
GO
