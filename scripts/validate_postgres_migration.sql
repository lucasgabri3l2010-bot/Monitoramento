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
SELECT format(
    'SELECT %L AS table_name, %L AS column_name, max(%I) AS table_max, '
    's.last_value AS sequence_last_value FROM %I.%I, %I s WHERE s.sequence_name = pg_get_serial_sequence(%L::regclass, %L) GROUP BY s.last_value',
    cols.table_name,
    cols.column_name,
    cols.column_name,
    cols.table_schema,
    cols.table_name,
    cols.column_name,
    cols.table_schema,
    cols.column_name
)
FROM information_schema.columns cols
WHERE cols.table_schema = 'public'
  AND pg_get_serial_sequence(
      format('%I.%I', cols.table_schema, cols.table_name),
      cols.column_name
  ) IS NOT NULL
ORDER BY cols.table_name, cols.ordinal_position
\gexec
