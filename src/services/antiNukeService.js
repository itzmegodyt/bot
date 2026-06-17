import { logger } from '../utils/logger.js';

// Simple anti-nuke protection: track destructive actions per executor
// and take automated mitigation when thresholds are exceeded.

const DEFAULT_POLICY = Object.freeze({
  windowMs: 10 * 1000, // time window to count actions
  threshold: 5, // number of destructive actions to trigger mitigation
  mitigations: {
    ban: true, // attempt to ban offending user
    removeRoles: true // attempt to remove elevated roles from offending user
  }
});

const actionStores = new Map(); // guildId -> Map<userId, {count, firstAt, timer}>

function getStore(guildId) {
  if (!actionStores.has(guildId)) actionStores.set(guildId, new Map());
  return actionStores.get(guildId);
}

function scheduleDecay(guildId, userId, windowMs) {
  const store = getStore(guildId);
  const entry = store.get(userId);
  if (!entry) return;
  if (entry.timer) clearTimeout(entry.timer);
  entry.timer = setTimeout(() => store.delete(userId), windowMs + 1000);
}

async function mitigate(guild, executor, reason = 'Anti-nuke triggered') {
  try {
    const member = await guild.members.fetch(executor.id).catch(() => null);
    if (DEFAULT_POLICY.mitigations.ban && member && member.bannable) {
      await guild.members.ban(member, { reason });
      logger.warn('Anti-nuke: Banned offending member', { guild: guild.id, user: executor.id });
      return;
    }

    if (DEFAULT_POLICY.mitigations.removeRoles && member) {
      const dangerous = member.roles.cache.filter(r => r.editable && (r.permissions.has('Administrator') || r.permissions.has('ManageGuild') || r.permissions.has('ManageRoles')));
      if (dangerous.size > 0) {
        for (const role of dangerous.values()) {
          try { await member.roles.remove(role, 'Anti-nuke mitigation'); } catch (err) { /* ignore */ }
        }
        logger.warn('Anti-nuke: Removed elevated roles from offender', { guild: guild.id, user: executor.id });
        return;
      }
    }

    logger.warn('Anti-nuke: No mitigation applied (insufficient permissions)', { guild: guild.id, user: executor.id });
  } catch (error) {
    logger.error('Error while running anti-nuke mitigation', { error, guild: guild.id, user: executor?.id });
  }
}

async function recordDestructiveAction(guild, executor, actionName) {
  if (!guild || !executor) return;
  const guildId = guild.id;
  const userId = executor.id;
  const store = getStore(guildId);
  const now = Date.now();

  let entry = store.get(userId);
  if (!entry) {
    entry = { count: 0, firstAt: now, timer: null };
    store.set(userId, entry);
  }

  entry.count += 1;
  scheduleDecay(guildId, userId, DEFAULT_POLICY.windowMs);

  logger.info('Anti-nuke: recorded action', { guild: guildId, user: userId, action: actionName, count: entry.count });

  if (entry.count >= DEFAULT_POLICY.threshold) {
    // trigger mitigation
    await mitigate(guild, executor, `Triggered anti-nuke (${entry.count} ${actionName} actions within ${DEFAULT_POLICY.windowMs}ms)`);
    store.delete(userId);
  }
}

export default {
  async handleRoleDelete(role) {
    try {
      const guild = role.guild;
      if (!guild) return;
      const logs = await guild.fetchAuditLogs({ type: 32, limit: 1 }).catch(() => null); // ROLE_DELETE
      const entry = logs?.entries?.first?.();
      const executor = entry?.executor || null;
      if (executor) await recordDestructiveAction(guild, executor, 'role_delete');
    } catch (error) {
      logger.error('Anti-nuke error on roleDelete', { error });
    }
  },

  async handleChannelDelete(channel) {
    try {
      const guild = channel.guild;
      if (!guild) return;
      const logs = await guild.fetchAuditLogs({ type: 12, limit: 1 }).catch(() => null); // CHANNEL_DELETE
      const entry = logs?.entries?.first?.();
      const executor = entry?.executor || null;
      if (executor) await recordDestructiveAction(guild, executor, 'channel_delete');
    } catch (error) {
      logger.error('Anti-nuke error on channelDelete', { error });
    }
  }
};
