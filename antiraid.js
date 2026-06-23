// antiRaid.js
const { Events, PermissionFlagsBits } = require('discord.js');

// In-memory trackers (Resets when bot restarts, which is fine for active raids)
const channelCreationTracker = new Map();
const mentionSpamTracker = new Map();

const MAX_CHANNELS_PER_MINUTE = 3; // Tune this: How many channels in 60s before action?
const MAX_MENTIONS_PER_5_SECONDS = 4; // Tune this: How many @everyone in 5s before action?

module.exports = {
    name: Events.ClientReady,
    once: true,
    execute(client) {
        console.log('Hard Anti-Raid module loaded.');

        // ---------------------------------------------------------
        // 1. ANTI-CHANNEL SPAM (Stops the raid bot from making channels)
        // ---------------------------------------------------------
        client.on(Events.ChannelCreate, async (channel) => {
            if (!channel.guild) return;

            const now = Date.now();
            const guildId = channel.guild.id;
            const userId = channel.creatorId; // The bot/user who made it

            if (!channelCreationTracker.has(guildId)) {
                channelCreationTracker.set(guildId, []);
            }

            const timestamps = channelCreationTracker.get(guildId);
            timestamps.push({ time: now, userId });

            // Filter out actions older than 60 seconds
            const recentActions = timestamps.filter(t => now - t.time < 60000);
            channelCreationTracker.set(guildId, recentActions);

            if (recentActions.length >= MAX_CHANNELS_PER_MINUTE) {
                // RAID DETECTED: Lockdown the server instantly
                try {
                    await channel.guild.roles.everyone.setPermissions([
                        PermissionFlagsBits.ReadMessageHistory
                        // Removes: Create Channels, Send Messages, Mention @everyone
                    ]);
                    console.log(`[ANTI-RAID] Locked down guild: ${guildId} due to channel spam.`);

                    // Optional: You can make the bot post an alert in a log channel here
                } catch (err) {
                    console.error('Failed to lockdown guild (Missing Permissions?).', err);
                }
            }
        });

        // ---------------------------------------------------------
        // 2. ANTI-@EVERYONE SPAM (Stops the ping spam)
        // ---------------------------------------------------------
        const checkMentionSpam = async (message) => {
            if (!message.guild || message.author.bot) return; // Ignore bots to prevent loops, or remove this if the raider IS a bot

            // Check if the message actually contains @everyone or @here
            if (!message.mentions.everyone) return;

            const now = Date.now();
            const guildId = message.guild.id;
            const userId = message.author.id;

            if (!mentionSpamTracker.has(guildId)) {
                mentionSpamTracker.set(guildId, []);
            }

            const timestamps = mentionSpamTracker.get(guildId);
            timestamps.push({ time: now, userId });

            // Filter out pings older than 5 seconds
            const recentPings = timestamps.filter(t => now - t.time < 5000);
            mentionSpamTracker.set(guildId, recentPings);

            if (recentPings.length >= MAX_MENTIONS_PER_5_SECONDS) {
                // SPAM DETECTED: Mute the user instantly
                try {
                    await message.member.roles.add('1518804100827844710', 'Anti-Nuke: Mention spam'); // REPLACE WITH YOUR MUTE ROLE ID
                    await message.member.timeout(24 * 60 * 60 * 1000, 'Anti-Nuke: Mention spam'); // 24 hour timeout

                    // Delete the spam messages
                    await message.channel.bulkDelete(100, true).catch(() => {});
                    console.log(`[ANTI-RAID] Timed out ${userId} in ${guildId} for mention spam.`);
                } catch (err) {
                    console.error('Failed to mute spammer (Missing Permissions?).', err);
                }
            }
        };

        // Listen for BOTH new messages AND edited messages (Raiders often edit old messages to bypass filters)
        client.on(Events.MessageCreate, checkMentionSpam);
        client.on(Events.MessageUpdate, checkMentionSpam);
    }
};