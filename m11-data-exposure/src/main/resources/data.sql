-- Synthetic data only. Runs after Hibernate DDL (defer-datasource-initialization).
-- The values below are fabricated; they exist so the exposure PoC has something to over-fetch.

INSERT INTO subscriber (id, username, email, phone, password_hash, refresh_token, internal_risk_score,
                        gdpr_erasure_requested, inn, snils, espd_token_hash)
  VALUES ('USR-0001', 'alice', 'alice@example.invalid', '+7-000-000-0001',
          'argon2:19$3mbs00$fake/fake/fake$fakefakefakefakefakefake==',
          'rt_placeholder_0001_do_not_use', 12, FALSE, '7701234567', '112-233-445-95',
          'espdhash_placeholder_0001');

INSERT INTO subscriber (id, username, email, phone, password_hash, refresh_token, internal_risk_score,
                        gdpr_erasure_requested, inn, snils, espd_token_hash)
  VALUES ('USR-0002', 'bob', 'bob@example.invalid', '+7-000-000-0002',
          'argon2:19$3mbs00$fake2/fake2/fake2$fakefakefakefakefakefake2==',
          'rt_placeholder_0002_do_not_use', 47, TRUE, '7707654321', '556-677-889-01',
          'espdhash_placeholder_0002');

INSERT INTO subscription_row (id, plan, monthly_price, activated_at, subscriber_id)
  VALUES ('SUB-1001', 'ESPD-BASIC', 990.00, '2026-01-04T09:15:00Z', 'USR-0001');
INSERT INTO subscription_row (id, plan, monthly_price, activated_at, subscriber_id)
  VALUES ('SUB-1002', 'ESPD-PRO', 2490.00, '2026-02-11T13:40:00Z', 'USR-0001');
INSERT INTO subscription_row (id, plan, monthly_price, activated_at, subscriber_id)
  VALUES ('SUB-2001', 'ESPD-BASIC', 990.00, '2026-03-02T08:00:00Z', 'USR-0002');
