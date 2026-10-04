-- - template: use the manager ExportSql action before running this file
-- - mysql 8: run manually as an administrator after changing stored routines, triggers or events
-- - replace {{DATABASE}} consistently; all four catalogue tables update in one transaction
-- - do not grant this refresh operation to the mcp account
START TRANSACTION;
DELETE FROM `{{METADATA_SCHEMA}}`.routines;
INSERT INTO `{{METADATA_SCHEMA}}`.routines
SELECT ROUTINE_NAME AS routine_name, ROUTINE_TYPE AS routine_type, NULL AS parameter_list,
       DTD_IDENTIFIER AS returns_clause, ROUTINE_DEFINITION AS routine_body, SQL_DATA_ACCESS AS sql_data_access,
       IS_DETERMINISTIC AS is_deterministic, SECURITY_TYPE AS security_type, SQL_MODE AS sql_mode,
       ROUTINE_COMMENT AS comment, DEFINER AS definer, CREATED AS created, LAST_ALTERED AS modified,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='{{DATABASE}}';

DELETE FROM `{{METADATA_SCHEMA}}`.parameters;
INSERT INTO `{{METADATA_SCHEMA}}`.parameters
SELECT SPECIFIC_NAME AS routine_name, ROUTINE_TYPE AS routine_type, ORDINAL_POSITION AS ordinal_position,
       PARAMETER_MODE AS parameter_mode, PARAMETER_NAME AS parameter_name, DATA_TYPE AS data_type,
       DTD_IDENTIFIER AS dtd_identifier, CHARACTER_SET_NAME AS character_set_name, COLLATION_NAME AS collation_name
FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA='{{DATABASE}}';

DELETE FROM `{{METADATA_SCHEMA}}`.triggers;
INSERT INTO `{{METADATA_SCHEMA}}`.triggers
SELECT TRIGGER_NAME AS name, EVENT_OBJECT_TABLE AS table_name, ACTION_TIMING AS timing,
       EVENT_MANIPULATION AS event, ACTION_ORDER AS action_order, ACTION_STATEMENT AS body,
       SQL_MODE AS sql_mode, DEFINER AS definer, CREATED AS created,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='{{DATABASE}}';

DELETE FROM `{{METADATA_SCHEMA}}`.events;
INSERT INTO `{{METADATA_SCHEMA}}`.events
SELECT EVENT_NAME AS name, EVENT_DEFINITION AS body, EVENT_TYPE AS event_type,
       EXECUTE_AT AS execute_at, INTERVAL_VALUE AS interval_value, INTERVAL_FIELD AS interval_field,
       STARTS AS starts, ENDS AS ends, STATUS AS status, ON_COMPLETION AS on_completion,
       SQL_MODE AS sql_mode, DEFINER AS definer, TIME_ZONE AS time_zone, EVENT_COMMENT AS comment,
       CREATED AS created, LAST_ALTERED AS modified, LAST_EXECUTED AS last_executed,
       CHARACTER_SET_CLIENT AS character_set_client, COLLATION_CONNECTION AS collation_connection, DATABASE_COLLATION AS db_collation
FROM information_schema.EVENTS WHERE EVENT_SCHEMA='{{DATABASE}}';

UPDATE `{{METADATA_SCHEMA}}`.catalog_state SET source_schema='{{DATABASE}}', refreshed_at_utc=UTC_TIMESTAMP(6) WHERE id=1;
COMMIT;
