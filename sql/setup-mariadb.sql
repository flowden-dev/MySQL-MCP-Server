-- - template: use the manager ExportSql action before running this file
-- - run manually as a database administrator, never through the mcp server
-- - target: mariadb 10.4+; replace {{DATABASE}} and both password placeholders
-- - use fresh dedicated accounts; CREATE USER deliberately fails if one already exists
-- - the locked metadata owner cannot log in and is not the mcp account

CREATE DATABASE IF NOT EXISTS `{{METADATA_SCHEMA}}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
-- - usernames must be unique across hosts to prevent inherited grants from another account
CREATE TEMPORARY TABLE `{{METADATA_SCHEMA}}`.setup_guard (valid TINYINT NOT NULL CHECK (valid=1));
INSERT INTO `{{METADATA_SCHEMA}}`.setup_guard
SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User IN ('{{READER_USER}}','{{OWNER_USER}}')),0,1);
DROP TEMPORARY TABLE `{{METADATA_SCHEMA}}`.setup_guard;
CREATE USER '{{OWNER_USER}}'@'localhost' IDENTIFIED BY 'REPLACE_METADATA_OWNER_PASSWORD' ACCOUNT LOCK;
GRANT SELECT ON mysql.proc TO '{{OWNER_USER}}'@'localhost';
GRANT SELECT, TRIGGER, EVENT ON `{{DATABASE_GRANT}}`.* TO '{{OWNER_USER}}'@'localhost';

CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER='{{OWNER_USER}}'@'localhost' SQL SECURITY DEFINER VIEW `{{METADATA_SCHEMA}}`.routines AS
SELECT name AS routine_name, type AS routine_type,
       CONVERT(param_list USING utf8mb4) AS parameter_list, CONVERT(returns USING utf8mb4) AS returns_clause,
       CONVERT(body_utf8 USING utf8mb4) AS routine_body, sql_data_access, is_deterministic, security_type,
       sql_mode, comment, definer, created, modified, character_set_client, collation_connection, db_collation
FROM mysql.proc WHERE db='{{DATABASE}}';

CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER='{{OWNER_USER}}'@'localhost' SQL SECURITY DEFINER VIEW `{{METADATA_SCHEMA}}`.parameters AS
SELECT SPECIFIC_NAME AS routine_name, ROUTINE_TYPE AS routine_type, ORDINAL_POSITION AS ordinal_position,
       PARAMETER_MODE AS parameter_mode, PARAMETER_NAME AS parameter_name, DATA_TYPE AS data_type,
       DTD_IDENTIFIER AS dtd_identifier, CHARACTER_SET_NAME AS character_set_name, COLLATION_NAME AS collation_name
FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA='{{DATABASE}}';

CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER='{{OWNER_USER}}'@'localhost' SQL SECURITY DEFINER VIEW `{{METADATA_SCHEMA}}`.triggers AS
SELECT TRIGGER_NAME AS name, EVENT_OBJECT_TABLE AS table_name, ACTION_TIMING AS timing,
       EVENT_MANIPULATION AS event, ACTION_ORDER AS action_order, ACTION_STATEMENT AS body,
       SQL_MODE AS sql_mode, DEFINER AS definer, CREATED AS created,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='{{DATABASE}}';

CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER='{{OWNER_USER}}'@'localhost' SQL SECURITY DEFINER VIEW `{{METADATA_SCHEMA}}`.events AS
SELECT EVENT_NAME AS name, EVENT_DEFINITION AS body, EVENT_TYPE AS event_type,
       EXECUTE_AT AS execute_at, INTERVAL_VALUE AS interval_value, INTERVAL_FIELD AS interval_field,
       STARTS AS starts, ENDS AS ends, STATUS AS status, ON_COMPLETION AS on_completion,
       SQL_MODE AS sql_mode, DEFINER AS definer, TIME_ZONE AS time_zone, EVENT_COMMENT AS comment,
       CREATED AS created, LAST_ALTERED AS modified, LAST_EXECUTED AS last_executed,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.EVENTS WHERE EVENT_SCHEMA='{{DATABASE}}';

CREATE USER '{{READER_USER}}'@'{{READER_HOST}}' IDENTIFIED BY 'REPLACE_MCP_DATABASE_PASSWORD' WITH MAX_USER_CONNECTIONS 2;
GRANT SELECT, SHOW VIEW ON `{{DATABASE_GRANT}}`.* TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.routines TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.parameters TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.triggers TO '{{READER_USER}}'@'{{READER_HOST}}';
GRANT SELECT ON `{{METADATA_SCHEMA}}`.events TO '{{READER_USER}}'@'{{READER_HOST}}';

-- - no EXECUTE, FILE, PROCESS, SUPER, DML, DDL, roles, proxy grants or GRANT OPTION
-- - no FLUSH PRIVILEGES is necessary for CREATE USER and GRANT
