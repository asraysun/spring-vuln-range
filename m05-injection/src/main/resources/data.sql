-- Synthetic demo data only. Runs after Hibernate DDL (spring.jpa.defer-datasource-initialization).
-- The credentials table exists so that the SQL injection PoC has something to UNION against:
-- it demonstrates why "the app user can read the secrets table" is itself a finding (checklist 3/5).

INSERT INTO subscription (id, owner_username, tenant_id, plan, customer_email, monthly_price, created_at)
  VALUES ('SUB-1001', 'alice',   'T-100', 'ESPD-BASIC',  'alice@example.invalid',   990.00,  '2026-01-04T09:15:00Z');
INSERT INTO subscription (id, owner_username, tenant_id, plan, customer_email, monthly_price, created_at)
  VALUES ('SUB-1002', 'alice',   'T-100', 'ESPD-PRO',    'alice@example.invalid',  2490.00,  '2026-02-11T13:40:00Z');
INSERT INTO subscription (id, owner_username, tenant_id, plan, customer_email, monthly_price, created_at)
  VALUES ('SUB-2001', 'bob',     'T-200', 'ESPD-BASIC',  'bob@example.invalid',     990.00,  '2026-03-02T08:00:00Z');
INSERT INTO subscription (id, owner_username, tenant_id, plan, customer_email, monthly_price, created_at)
  VALUES ('SUB-3001', 'mallory', 'T-300', 'ESPD-TRIAL',  'mallory@example.invalid',   0.00,  '2026-04-19T17:25:00Z');

CREATE TABLE IF NOT EXISTS integration_credentials (
    service_name VARCHAR(64) NOT NULL,
    env          VARCHAR(16) NOT NULL,
    api_key      VARCHAR(128) NOT NULL
);

DELETE FROM integration_credentials;
INSERT INTO integration_credentials (service_name, env, api_key)
  VALUES ('espd-gateway', 'dev',  'dev-placeholder-not-a-secret-0001');
INSERT INTO integration_credentials (service_name, env, api_key)
  VALUES ('espd-gateway', 'prod', 'prod-placeholder-not-a-secret-9999');
