\pset pager off
\echo '=== SERVER ==='
SELECT current_database() AS database_name, version() AS postgres_version;

\echo '=== TABLES ==='
SELECT schemaname, tablename
FROM pg_catalog.pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

\echo '=== EXACT ROW COUNTS ==='
SELECT format(
    'SELECT %L AS table_name, count(*) AS row_count FROM %I.%I;',
    tablename,
    schemaname,
    tablename
)
FROM pg_catalog.pg_tables
WHERE schemaname = 'public'
ORDER BY tablename
\gexec

\echo '=== PRIMARY AND FOREIGN KEYS ==='
SELECT
    tc.table_name,
    tc.constraint_name,
    tc.constraint_type,
    kcu.column_name,
    ccu.table_name AS referenced_table,
    ccu.column_name AS referenced_column
FROM information_schema.table_constraints tc
LEFT JOIN information_schema.key_column_usage kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.constraint_schema = kcu.constraint_schema
LEFT JOIN information_schema.constraint_column_usage ccu
    ON tc.constraint_name = ccu.constraint_name
    AND tc.constraint_schema = ccu.constraint_schema
WHERE tc.table_schema = 'public'
  AND tc.constraint_type IN ('PRIMARY KEY', 'FOREIGN KEY', 'UNIQUE')
ORDER BY tc.table_name, tc.constraint_type, tc.constraint_name, kcu.ordinal_position;

\echo '=== INDEXES ==='
SELECT tablename, indexname, indexdef
FROM pg_catalog.pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

\echo '=== SEQUENCES AND OWNERSHIP ==='
SELECT
    sequence_schema,
    sequence_name,
    data_type,
    start_value,
    minimum_value,
    maximum_value,
    increment
FROM information_schema.sequences
WHERE sequence_schema = 'public'
ORDER BY sequence_name;

\echo '=== SEQUENCE VALUES VS TABLE MAX ==='
WITH sequence_columns AS (
    SELECT
        cols.table_schema,
        cols.table_name,
        cols.column_name,
        cols.ordinal_position,
        pg_get_serial_sequence(
            format('%I.%I', cols.table_schema, cols.table_name),
            cols.column_name
        ) AS sequence_name
    FROM information_schema.columns AS cols
    WHERE cols.table_schema = 'public'
),
sequence_metadata AS (
    SELECT
        sequence_columns.*,
        sequence_namespace.nspname AS sequence_schema,
        sequence_class.relname AS sequence_relation,
        sequence_parameters.seqincrement AS increment_by
    FROM sequence_columns
    JOIN pg_catalog.pg_class AS sequence_class
      ON sequence_class.oid = sequence_columns.sequence_name::regclass
    JOIN pg_catalog.pg_namespace AS sequence_namespace
      ON sequence_namespace.oid = sequence_class.relnamespace
    JOIN pg_catalog.pg_sequence AS sequence_parameters
      ON sequence_parameters.seqrelid = sequence_class.oid
    WHERE sequence_columns.sequence_name IS NOT NULL
)
SELECT format(
    $sql$
WITH sequence_state AS (
    SELECT
        sequence_data.last_value::bigint AS last_value,
        sequence_data.is_called,
        %L::bigint AS increment_by
    FROM %I.%I AS sequence_data
),
calculated AS (
    SELECT
        last_value,
        CASE
            WHEN is_called THEN last_value + increment_by
            ELSE last_value
        END AS next_sequence_value
    FROM sequence_state
)
SELECT
    %L AS table_name,
    %L AS column_name,
    %L AS sequence_name,
    (SELECT max(%I) FROM %I.%I) AS table_max,
    calculated.last_value AS sequence_last_value,
    calculated.next_sequence_value,
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM %I.%I AS target
            WHERE target.%I = calculated.next_sequence_value
        ) THEN 'COLLISION_RISK'
        ELSE 'SAFE'
    END AS status
FROM calculated
$sql$,
    increment_by,
    sequence_schema,
    sequence_relation,
    table_name,
    column_name,
    sequence_name,
    column_name,
    table_schema,
    table_name,
    table_schema,
    table_name,
    column_name
)
FROM sequence_metadata
ORDER BY table_name, ordinal_position
\gexec
