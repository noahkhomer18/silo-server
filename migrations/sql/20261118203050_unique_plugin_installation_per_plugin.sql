-- +goose Up
-- One installation per plugin. Installs decide between creating and replacing
-- by reading plugin_installations, so two servers auto-installing a default
-- plugin at once, or an archive link for an installed plugin, could add a
-- second row, after which every install or update of that plugin failed.
--
-- A deployment that already has duplicates keeps one row per plugin: one
-- with an enabled sign-in binding, then one with linked sign-in identities,
-- then one an admin configured (settings or a sign-in binding), then one with
-- a stored package, then an enabled one, then the oldest. Request connections
-- move to the kept row, which also takes library chain placements, task
-- bindings and saved task schedules it lacks. A stored package does not move
-- (the same version can be a different build), nor do sign-in identities (see
-- below). The others are deleted with their settings, sign-in bindings,
-- remaining chain entries and state (ON DELETE CASCADE): settings are
-- encrypted under the installation id, and a delivered event leaves no
-- delivery row, so moving a pending delivery could deliver the event to the
-- kept row a second time. Events still pending only for a deleted row are
-- dropped. Files on disk are not removed.
--
-- Block writes and row locks (plain reads continue) until the index exists,
-- so a server still running the previous release cannot add a duplicate after
-- the cleanup. EXCLUSIVE also waits out a row lock taken before a write, such
-- as a settings save's, which would otherwise deadlock with the cleanup.
-- A provider sign-in locks the account before the installation
-- (OpenIdentitySession), so the accounts linked to a duplicated plugin, whose
-- sign-ins this cleanup may revoke, are locked before any table.
SELECT u.id FROM users u
WHERE u.id IN (
    SELECT a.user_id
    FROM plugin_auth_identities a
    JOIN plugin_installations i ON i.id = a.plugin_installation_id
    WHERE i.kind = 'plugin'
      AND i.plugin_id IN (
          SELECT plugin_id FROM plugin_installations WHERE kind = 'plugin'
          GROUP BY plugin_id HAVING count(*) > 1)
)
ORDER BY u.id
FOR UPDATE;

-- Chain and task-binding edits write their own row before their foreign key
-- locks the installation, so those tables are locked first, in the same order.
LOCK TABLE library_provider_chains, plugin_task_bindings IN EXCLUSIVE MODE;
LOCK TABLE plugin_installations IN EXCLUSIVE MODE;

CREATE TEMP TABLE ranked_plugin_installations ON COMMIT DROP AS
SELECT i.id,
       i.plugin_id,
       row_number() OVER (
           PARTITION BY i.plugin_id
           ORDER BY EXISTS (SELECT 1 FROM plugin_auth_bindings b WHERE b.plugin_installation_id = i.id AND b.enabled) DESC,
                    EXISTS (SELECT 1 FROM plugin_auth_identities p WHERE p.plugin_installation_id = i.id) DESC,
                    (EXISTS (SELECT 1 FROM plugin_runtime_configs c WHERE c.plugin_installation_id = i.id)
                     OR EXISTS (SELECT 1 FROM plugin_auth_bindings b WHERE b.plugin_installation_id = i.id)) DESC,
                    EXISTS (SELECT 1 FROM plugin_archives a WHERE a.plugin_installation_id = i.id) DESC,
                    i.enabled DESC,
                    i.id ASC
       ) AS rank
FROM plugin_installations i
WHERE i.kind = 'plugin';

-- request_integrations.installation_id has no foreign key.
UPDATE request_integrations r
SET installation_id = kept.id
FROM ranked_plugin_installations dup
JOIN ranked_plugin_installations kept ON kept.plugin_id = dup.plugin_id AND kept.rank = 1
WHERE dup.rank > 1 AND r.installation_id = dup.id;

-- Sign-in identities do not move: a deleted duplicate may have been set up
-- for another directory, where the same subject names a different person.
-- Sessions and device approvals made through a deleted identity are revoked.
-- A user whose account the kept row links to the same subject keeps the rest
-- of its sign-ins, which the kept provider still checks; every other user
-- linked through a deleted duplicate loses the provider's checks with it, so
-- that account's sign-ins are all revoked: it signs in again.
CREATE TEMP TABLE dropped_plugin_auth_identities ON COMMIT DROP AS
SELECT a.id AS dropped_id, a.user_id, k.id AS kept_identity_id
FROM plugin_auth_identities a
JOIN ranked_plugin_installations dup ON dup.id = a.plugin_installation_id AND dup.rank > 1
JOIN ranked_plugin_installations kept ON kept.plugin_id = dup.plugin_id AND kept.rank = 1
LEFT JOIN plugin_auth_identities k
    ON k.plugin_installation_id = kept.id AND k.external_subject = a.external_subject AND k.user_id = a.user_id;

-- The affected accounts are locked (again, for one linked since the lock
-- above) before anything is revoked, as every sign-out locks the account
-- first: an API key, Audiobookshelf token or device approval being issued
-- holds that row, so it either commits before this and is revoked below, or
-- waits and then finds its session revoked.
SELECT id FROM users
WHERE id IN (SELECT user_id FROM dropped_plugin_auth_identities)
ORDER BY id
FOR UPDATE;

-- Approvals are denied before sessions are revoked: collecting one locks the
-- request, so a collection in progress commits its session first and the
-- revocation that follows sees it, and a later one finds the request denied.
UPDATE device_login_requests SET status = 'denied', updated_at = now()
WHERE approved_identity_id IN (SELECT dropped_id FROM dropped_plugin_auth_identities) AND status = 'approved';
UPDATE auth_sessions SET revoked_at = now()
WHERE identity_id IN (SELECT dropped_id FROM dropped_plugin_auth_identities) AND revoked_at IS NULL;
-- Revoked as a password reset revokes an account (revokeAccountSessions):
-- login sessions on either side of an impersonation, Audiobookshelf and
-- Jellyfin-compatible sessions, API keys and device sign-in approvals.
CREATE TEMP TABLE displaced_plugin_auth_users ON COMMIT DROP AS
SELECT DISTINCT user_id FROM dropped_plugin_auth_identities WHERE kept_identity_id IS NULL;
UPDATE device_login_requests SET status = 'denied', updated_at = now()
WHERE approved_by_user_id IN (SELECT user_id FROM displaced_plugin_auth_users) AND status = 'approved';
UPDATE auth_sessions SET revoked_at = now()
WHERE (user_id IN (SELECT user_id FROM displaced_plugin_auth_users)
       OR impersonator_user_id IN (SELECT user_id FROM displaced_plugin_auth_users))
  AND revoked_at IS NULL;
UPDATE abs_sessions SET revoked_at = now()
WHERE user_id IN (SELECT user_id FROM displaced_plugin_auth_users) AND revoked_at IS NULL;
DELETE FROM jellycompat_sessions WHERE streamapp_user_id IN (SELECT user_id FROM displaced_plugin_auth_users);
DELETE FROM api_keys WHERE user_id IN (SELECT user_id FROM displaced_plugin_auth_users);

-- Library chain placements and scheduled-task bindings the kept row lacks are
-- taken from the best-ranked duplicate that has them.
INSERT INTO library_provider_chains
    (media_folder_id, priority, content_level, enabled, plugin_installation_id, capability_id, capability_type)
SELECT DISTINCT ON (kept.id, c.media_folder_id, c.capability_id, c.content_level)
       c.media_folder_id, c.priority, c.content_level, c.enabled, kept.id, c.capability_id, c.capability_type
FROM library_provider_chains c
JOIN ranked_plugin_installations dup ON dup.id = c.plugin_installation_id AND dup.rank > 1
JOIN ranked_plugin_installations kept ON kept.plugin_id = dup.plugin_id AND kept.rank = 1
ORDER BY kept.id, c.media_folder_id, c.capability_id, c.content_level, dup.rank
ON CONFLICT DO NOTHING;

INSERT INTO plugin_task_bindings (plugin_installation_id, capability_id, enabled, trigger)
SELECT DISTINCT ON (kept.id, t.capability_id) kept.id, t.capability_id, t.enabled, t.trigger
FROM plugin_task_bindings t
JOIN ranked_plugin_installations dup ON dup.id = t.plugin_installation_id AND dup.rank > 1
JOIN ranked_plugin_installations kept ON kept.plugin_id = dup.plugin_id AND kept.rank = 1
ORDER BY kept.id, t.capability_id, dup.rank
ON CONFLICT DO NOTHING;

-- A task schedule an admin saved is keyed plugin:<installation id>:<capability>
-- (pluginTaskKey); one the kept row lacks moves to it with its triggers. The
-- lock holds schedule edits (ReplaceSchedule locks a schedule row first) until
-- this commits, so none can add the kept row's key after the check below.
LOCK TABLE task_schedules IN EXCLUSIVE MODE;
CREATE TEMP TABLE moved_task_schedules ON COMMIT DROP AS
SELECT DISTINCT ON (new_key) old_key, new_key
FROM (
    SELECT s.task_key AS old_key,
           'plugin:' || kept.id || ':' || substr(s.task_key, length('plugin:' || dup.id || ':') + 1) AS new_key,
           dup.rank
    FROM task_schedules s
    JOIN ranked_plugin_installations dup ON dup.rank > 1 AND s.task_key LIKE 'plugin:' || dup.id || ':%'
    JOIN ranked_plugin_installations kept ON kept.plugin_id = dup.plugin_id AND kept.rank = 1
) candidates
WHERE NOT EXISTS (SELECT 1 FROM task_schedules k WHERE k.task_key = candidates.new_key)
ORDER BY new_key, rank;

UPDATE task_schedules s SET task_key = m.new_key FROM moved_task_schedules m WHERE s.task_key = m.old_key;
UPDATE task_triggers t SET task_key = m.new_key FROM moved_task_schedules m WHERE t.task_key = m.old_key;

DELETE FROM plugin_installations pi
USING ranked_plugin_installations dup
WHERE pi.id = dup.id AND dup.rank > 1;

CREATE UNIQUE INDEX idx_plugin_installations_plugin_id
    ON plugin_installations (plugin_id)
    WHERE kind = 'plugin';

-- +goose Down
DROP INDEX IF EXISTS idx_plugin_installations_plugin_id;
