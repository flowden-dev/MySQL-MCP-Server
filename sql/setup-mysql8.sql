-- - template: use the manager ExportSql action before running this file
-- - run manually as an administrator on mysql 8.0.20+ or mysql 8.4
-- - replace {{DATABASE}} and the reader password placeholder; use a fresh dedicated account
-- - `{{METADATA_SCHEMA}}` must be empty before this setup; back up any old catalogue first
-- - mysql information_schema checks invoker privileges even behind definer views
-- - use a read-only metadata snapshot, refreshed manually after schema changes
-- - the reader receives no EXECUTE, TRIGGER, EVENT or global SHOW_ROUTINE privileges

CREATE DATABASE IF NOT EXISTS `{{METADATA_SCHEMA}}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE TEMPORARY TABLE `{{METADATA_SCHEMA}}`.setup_guard (valid TINYINT NOT NULL CHECK (valid=1));
INSERT INTO `{{METADATA_SCHEMA}}`.setup_guard
SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User='{{READER_USER}}'),0,1);
DROP TEMPORARY TABLE `{{METADATA_SCHEMA}}`.setup_guard;
CREATE TABLE `{{METADATA_SCHEMA}}`.routines ENGINE=InnoDB AS
SELECT ROUTINE_NAME AS routine_name, ROUTINE_TYPE AS routine_type, NULL AS parameter_list,
       DTD_IDENTIFIER AS returns_clause, ROUTINE_DEFINITION AS routine_body, SQL_DATA_ACCESS AS sql_data_access,
       IS_DETERMINISTIC AS is_deterministic, SECURITY_TYPE AS security_type, SQL_MODE AS sql_mode,
       ROUTINE_COMMENT AS comment, DEFINER AS definer, CREATED AS created, LAST_ALTERED AS modified,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='{{DATABASE}}';

CREATE TABLE `{{METADATA_SCHEMA}}`.parameters ENGINE=InnoDB AS
SELECT SPECIFIC_NAME AS routine_name, ROUTINE_TYPE AS routine_type, ORDINAL_POSITION AS ordinal_position,
       PARAMETER_MODE AS parameter_mode, PARAMETER_NAME AS parameter_name, DATA_TYPE AS data_type,
       DTD_IDENTIFIER AS dtd_identifier, CHARACTER_SET_NAME AS character_set_name, COLLATION_NAME AS collation_name
FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA='{{DATABASE}}';

CREATE TABLE `{{METADATA_SCHEMA}}`.triggers ENGINE=InnoDB AS
SELECT TRIGGER_NAME AS name, EVENT_OBJECT_TABLE AS table_name, ACTION_TIMING AS timing,
       EVENT_MANIPULATION AS event, ACTION_ORDER AS action_order, ACTION_STATEMENT AS body,
       SQL_MODE AS sql_mode, DEFINER AS definer, CREATED AS created,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='{{DATABASE}}';

CREATE TABLE `{{METADATA_SCHEMA}}`.events ENGINE=InnoDB AS
SELECT EVENT_NAME AS name, EVENT_DEFINITION AS body, EVENT_TYPE AS event_type,
       EXECUTE_AT AS execute_at, INTERVAL_VALUE AS interval_value, INTERVAL_FIELD AS interval_field,
       STARTS AS starts, ENDS AS ends, STATUS AS status, ON_COMPLETION AS on_completion,
       SQL_MODE AS sql_mode, DEFINER AS definer, TIME_ZONE AS time_zone, EVENT_COMMENT AS comment,
       CREATED AS created, LAST_ALTERED AS modified, LAST_EXECUTED AS last_executed,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.EVENTS WHERE EVENT_SCHEMA='{{DATABASE}}';

ALTER TABLE `{{METADATA_SCHEMA}}`.routines ADD PRIMARY KEY (routine_name, routine_type);
ALTER TABLE `{{METADATA_SCHEMA}}`.parameters ADD PRIMARY KEY (routine_name, routine_type, ordinal_position);
ALTER TABLE `{{METADATA_SCHEMA}}`.triggers ADD PRIMARY KEY (name);
ALTER TABLE `{{METADATA_SCHEMA}}`.events ADD PRIMARY KEY (name);
CREATE TABLE `{{METADATA_SCHEMA}}`.catalog_state (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    source_schema VARCHAR(64) NOT NULL,
    refreshed_at_utc DATETIME(6) NOT NULL
) ENGINE=InnoDB;
INSERT INTO `{{METADATA_SCHEMA}}`.catalog_state VALUES (1, '{{DATABASE}}', UTC_TIMESTAMP(6));

CREATE USER '{{READER_USER}}'@'{{READER_HOST}}' IDENTIFIED BY 'REPLACE_MCP_DATABASE_PASSWORD' WITH MAX_USER_CONNECTIONS 2;
-- - escape database wildcard characters unless mysql treats them literally
SET @mcp_schema_scope = IF(@@partial_revokes, '{{DATABASE}}', REPLACE('{{DATABASE}}','_',CONCAT(CHAR(92),'_')));
SET @mcp_reader_grant = CONCAT('GRANT SELECT, SHOW VIEW ON `', @mcp_schema_scope, '`.* TO ''{{READER_USER}}''@''{{READER_HOST}}''');
PREPARE mcp_setup_grant FROM @mcp_reader_grant;
EXECUTE mcp_setup_grant;
DEALLOCATE PREPARE mcp_setup_grant;
SET @mcp_schema_scope = NULL, @mcp_reader_grant = NULL;
GRANT SELECT ON `{{METADATA_SCHEMA}}`.routines TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.parameters TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.triggers TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.events TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.catalog_state TO '{{READER_USER}}'@'{{READER_HOST}}';
