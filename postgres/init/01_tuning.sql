-- Mejoras para planner/estadísticas (seguro)
ALTER SYSTEM SET default_statistics_target = '200';

-- Evitar transacciones colgadas eternamente (seguro)
ALTER SYSTEM SET idle_in_transaction_session_timeout = '300000';

-- Si te interesa rastrear locks
ALTER SYSTEM SET log_lock_waits = 'on';
ALTER SYSTEM SET deadlock_timeout = '2s';

SELECT pg_reload_conf();
