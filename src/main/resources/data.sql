INSERT INTO roles (user_role)
SELECT 'USER'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE user_role = 'USER');

INSERT INTO roles (user_role)
SELECT 'MODERATOR'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE user_role = 'MODERATOR');

INSERT INTO roles (user_role)
SELECT 'ADMIN'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE user_role = 'ADMIN');

INSERT INTO creditional (username, email, password)
SELECT 'user', 'user@example.com', '$2a$10$hOGIUZLjxVgXwEHcGY9OPOazJbV899.Ay6cDMESs65LHQ3s3vS38a'
WHERE NOT EXISTS (SELECT 1 FROM creditional WHERE username = 'user');

INSERT INTO creditional (username, email, password)
SELECT 'alice', 'alice@example.com', '$2a$10$zwap6P4UjyCIerj6UWyh/OiJpGnIRTlvY4PjDTbzcBt7EDZfplAnO'
WHERE NOT EXISTS (SELECT 1 FROM creditional WHERE username = 'alice');

INSERT INTO creditional (username, email, password)
SELECT 'bob', 'bob@example.com', '$2a$10$xJsKIDZcTEsZFk0n1X0K5u8ojX4yKlVixMqj532mO8jmv314sNX3.'
WHERE NOT EXISTS (SELECT 1 FROM creditional WHERE username = 'bob');

INSERT INTO creditional (username, email, password)
SELECT 'moderator', 'moderator@example.com', '$2a$10$8CT59El7IMbkkYogCMxi6.CnFnXeMaSa8LqDVGyPleCjdqIiNlGSW'
WHERE NOT EXISTS (SELECT 1 FROM creditional WHERE username = 'moderator');

INSERT INTO creditional (username, email, password)
SELECT 'admin', 'admin@example.com', '$2a$10$A.3XyQ82gTVPmznHof/nyuLnLNmOLlvkMVgtmyND5hwDxcuA.jUEC'
WHERE NOT EXISTS (SELECT 1 FROM creditional WHERE username = 'admin');

INSERT INTO user_roles (user_id, role_id)
SELECT c.id, r.id
FROM creditional c
JOIN roles r ON r.user_role = 'USER'
WHERE c.username IN ('user', 'alice', 'bob')
  AND NOT EXISTS (
      SELECT 1
      FROM user_roles ur
      WHERE ur.user_id = c.id AND ur.role_id = r.id
  );

INSERT INTO user_roles (user_id, role_id)
SELECT c.id, r.id
FROM creditional c
JOIN roles r ON r.user_role = 'MODERATOR'
WHERE c.username = 'moderator'
  AND NOT EXISTS (
      SELECT 1
      FROM user_roles ur
      WHERE ur.user_id = c.id AND ur.role_id = r.id
  );

INSERT INTO user_roles (user_id, role_id)
SELECT c.id, r.id
FROM creditional c
JOIN roles r ON r.user_role = 'ADMIN'
WHERE c.username = 'admin'
  AND NOT EXISTS (
      SELECT 1
      FROM user_roles ur
      WHERE ur.user_id = c.id AND ur.role_id = r.id
  );
