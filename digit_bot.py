# digit_bot.py
# Digit Security Bot v4.0.0
# prefix: ,   |  strict anti-nuke/raid, 150+ cmds, roblox alerts

import discord
from discord.ext import commands, tasks
import asyncio, aiohttp, json, os, random, time, re, base64, math
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# ====================================================================
# CONFIG
# ====================================================================

PREFIX  = ","
NAME    = "Digit"
VER     = "4.0.0"

# 2 actions in 5 seconds = instant nuke response
THRESHOLDS = {
    "ban":            (2, 5),
    "kick":           (2, 5),
    "channel_delete": (2, 5),
    "channel_create": (2, 5),
    "role_delete":    (2, 5),
    "role_create":    (2, 5),
    "webhook_create": (1, 5),    # even 1 webhook = suspicious
    "member_prune":   (1, 10),
    "mention_everyone": (2, 10),
}

# bot-specific thresholds are tighter
BOT_THRESHOLDS = {
    "ban":            (1, 10),
    "channel_delete": (1, 5),
    "role_delete":    (1, 5),
}

RAID_THRESHOLD = 5    # accounts joining in...
RAID_WINDOW    = 8    # ...this many seconds = raid
SPAM_COUNT     = 5
SPAM_WINDOW    = 3
MENTION_MAX    = 5

ROBLOX_PLATFORMS = {
    "Windows": {
        "api_key": "WindowsPlayer",
        "dl":      "https://www.roblox.com/download/client",
    },
    "Mac": {
        "api_key": "MacPlayer",
        "dl":      "https://www.roblox.com/download/client?os=mac",
    },
    "Android": {
        "api_key": "AndroidApp",
        "dl":      "https://play.google.com/store/apps/details?id=com.roblox.client",
    },
    "iOS": {
        "api_key": "iOSApp",
        "dl":      "https://apps.apple.com/us/app/roblox/id431946152",
    },
    "Studio": {
        "api_key": "WindowsStudio64",
        "dl":      "https://www.roblox.com/download/studio",
    },
}

# ====================================================================
# STATE
# ====================================================================

_action_log   = defaultdict(lambda: defaultdict(list))
_raid_log     = defaultdict(list)
_raid_members = defaultdict(list)
_spam_log     = defaultdict(list)
_warns        = defaultdict(list)   # {reason, mod, time}
_notes_db     = defaultdict(list)
_mod_history  = defaultdict(list)
_whitelist    = set()
_quarantined  = {}                  # uid -> saved_roles
_nuke_track   = defaultdict(lambda: {"channels": [], "roles": [], "webhooks": [], "ts": 0})
_guild_cfg    = {}
_roblox_vers  = {}                  # {platform: {version, display, upload}}
_uptime       = time.time()

# ====================================================================
# CONFIG HELPERS
# ====================================================================

def load_cfg():
    global _guild_cfg
    if os.path.exists("config.json"):
        try:
            raw = open("config.json").read().strip()
            _guild_cfg = json.loads(raw) if raw else {}
        except Exception as e:
            print(f"[cfg] load error: {e}")
            _guild_cfg = {}
    return _guild_cfg

def save_cfg():
    with open("config.json", "w") as f:
        json.dump(_guild_cfg, f, indent=2)

def gcfg(gid):
    load_cfg()
    return _guild_cfg.get(str(gid), {})

def scfg(gid, key, val):
    load_cfg()
    g = str(gid)
    if g not in _guild_cfg:
        _guild_cfg[g] = {}
    _guild_cfg[g][key] = val
    save_cfg()

# ====================================================================
# UTILITIES
# ====================================================================

def over_threshold(uid, action, is_bot=False):
    src = BOT_THRESHOLDS if is_bot and action in BOT_THRESHOLDS else THRESHOLDS
    count, window = src.get(action, (3, 10))
    now = time.time()
    log = _action_log[uid][action]
    log[:] = [t for t in log if now - t < window]
    log.append(now)
    return len(log) >= count

def is_bot_admin(ctx):
    cfg = gcfg(ctx.guild.id)
    return (
        ctx.author.guild_permissions.administrator or
        ctx.author.id in cfg.get("bot_admins", [])
    )

def ba_or_perm(*perms):
    async def pred(ctx):
        if is_bot_admin(ctx):
            return True
        for p in perms:
            if getattr(ctx.author.guild_permissions, p, False):
                return True
        await ctx.send("No permission.", delete_after=4)
        return False
    return commands.check(pred)

def ba_only():
    async def pred(ctx):
        if is_bot_admin(ctx):
            return True
        await ctx.send("No permission.", delete_after=4)
        return False
    return commands.check(pred)

async def log(guild, embed):
    cid = gcfg(guild.id).get("log_channel")
    if cid:
        ch = guild.get_channel(int(cid))
        if ch:
            try: await ch.send(embed=embed)
            except: pass

def modlog(guild_id, uid, action, mod, reason):
    _mod_history[f"{guild_id}:{uid}"].append({
        "action": action, "mod": str(mod),
        "reason": reason,
        "time": datetime.now(timezone.utc).isoformat()
    })

async def do_timeout(member, minutes, reason):
    try:
        until = discord.utils.utcnow() + timedelta(minutes=minutes)
        await member.timeout(until, reason=reason)
        return True
    except discord.Forbidden:
        return False
    except Exception as e:
        print(f"[timeout] {e}")
        return False

async def do_lockdown(guild, lock):
    for ch in guild.channels:
        if not isinstance(ch, (discord.TextChannel, discord.ForumChannel)):
            continue
        try:
            ow = ch.overwrites_for(guild.default_role)
            ow.send_messages = False if lock else None
            await ch.set_permissions(
                guild.default_role, overwrite=ow,
                reason=f"[Digit] {'Lockdown' if lock else 'Unlock'}"
            )
        except: pass

def parse_uid(raw):
    cleaned = raw.strip().strip("{}").lstrip("<@!").rstrip(">").strip()
    return int(cleaned) if cleaned.isdigit() else None

def parse_duration(s):
    # returns seconds from strings like 10m, 2h, 1d, 30s
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    m = re.match(r"^(\d+)([smhd]?)$", s.lower())
    if not m: return None
    n, u = int(m.group(1)), m.group(2) or "m"
    return n * units.get(u, 60)

async def fetch_user_tag(uid):
    try:
        u = await bot.fetch_user(uid)
        return f"**{u}** (`{u.id}`)", u
    except:
        return f"`{uid}`", None

# ====================================================================
# AUTOBAN
# ====================================================================

def get_autoban(gid): return gcfg(gid).get("autoban_list", [])
def add_autoban(gid, uid):
    lst = get_autoban(gid)
    if uid not in lst: lst.append(uid)
    scfg(gid, "autoban_list", lst)
def rm_autoban(gid, uid):
    lst = get_autoban(gid)
    if uid in lst: lst.remove(uid)
    scfg(gid, "autoban_list", lst)

# ====================================================================
# ANTI-NUKE PUNISHMENT (fires within 1-2 seconds)
# ====================================================================

async def nuke_punishment(guild, user, reason):
    if not user: return

    # DM "Nice try." -- ONLY for nuke/raid, never for autoban
    try:
        dm = discord.Embed(
            title="Nice try.",
            description=(
                f"You attempted to **{reason}** in **{guild.name}**.\n"
                "Everything was caught, logged, and reversed.\n"
                "Enjoy the permanent ban."
            ),
            color=0xFF0000,
            timestamp=discord.utils.utcnow()
        )
        dm.set_footer(text=f"Digit v{VER} Anti-Nuke")
        await user.send(embed=dm)
    except: pass

    # Strip dangerous roles immediately
    DANGER = {"administrator","ban_members","kick_members","manage_channels",
              "manage_guild","manage_roles","manage_webhooks","manage_messages"}
    member = guild.get_member(user.id)
    if member:
        bad = [r for r in member.roles[1:] if any(getattr(r.permissions, p, False) for p in DANGER)]
        if bad:
            try: await member.remove_roles(*bad, reason="[Digit] Anti-Nuke strip")
            except: pass

    # Delete everything the nuker created (channels, roles, webhooks)
    track = _nuke_track.get(user.id, {})
    tasks_to_run = []

    for ch_id in track.get("channels", []):
        ch = guild.get_channel(ch_id)
        if ch:
            tasks_to_run.append(ch.delete(reason="[Digit] Nuke cleanup"))

    for role_id in track.get("roles", []):
        role = guild.get_role(role_id)
        if role:
            tasks_to_run.append(role.delete(reason="[Digit] Nuke cleanup"))

    if tasks_to_run:
        await asyncio.gather(*tasks_to_run, return_exceptions=True)

    _nuke_track.pop(user.id, None)

    # Ban within 1-2 seconds total from trigger
    try:
        await guild.ban(user, reason=f"[Digit] Anti-Nuke: {reason}", delete_message_days=1)
    except: pass

# ====================================================================
# BOT SETUP
# ====================================================================

intents = discord.Intents.all()
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)
load_cfg()

@bot.event
async def on_ready():
    print(f"\nDigit v{VER} -- online")
    print(f"Logged in as: {bot.user} ({bot.user.id})")
    print(f"Servers: {len(bot.guilds)}\n")
    await bot.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching, name=f"your server | {PREFIX}help"),
        status=discord.Status.dnd
    )
    try:
        s = await bot.tree.sync()
        print(f"Synced {len(s)} slash commands")
    except Exception as e:
        print(f"Sync error: {e}")
    roblox_check.start()

@bot.event
async def on_command_error(ctx, err):
    if isinstance(err, commands.MissingPermissions):
        await ctx.send("No permission.", delete_after=4)
    elif isinstance(err, (commands.MemberNotFound, commands.UserNotFound)):
        await ctx.send("User not found.", delete_after=4)
    elif isinstance(err, commands.MissingRequiredArgument):
        await ctx.send(f"Missing argument. Check `,help`.", delete_after=5)
    elif isinstance(err, commands.CommandOnCooldown):
        await ctx.send(f"Wait {err.retry_after:.1f}s.", delete_after=5)
    elif isinstance(err, (commands.CommandNotFound, commands.CheckFailure)):
        pass
    elif isinstance(err, commands.BadArgument):
        await ctx.send("Invalid argument.", delete_after=4)
    else:
        print(f"[ERR] {ctx.command}: {err}")

# ====================================================================
# ANTI-NUKE -- AUDIT LOG
# ====================================================================

@bot.event
async def on_audit_log_entry_create(entry):
    guild  = entry.guild
    user   = entry.user
    action = entry.action

    if not user or user.id == bot.user.id: return
    if user.id in _whitelist: return
    if not gcfg(guild.id).get("antinuke_enabled", True): return

    is_bot_acct = user.bot
    uid = user.id

    # Track things the user is creating so we can reverse them
    now = time.time()
    track = _nuke_track[uid]
    if track["ts"] == 0: track["ts"] = now
    if now - track["ts"] > 30:   # reset if it's been a while
        track["channels"].clear(); track["roles"].clear()
        track["webhooks"].clear(); track["ts"] = now

    if action == discord.AuditLogAction.channel_create and entry.target:
        track["channels"].append(entry.target.id)
    elif action == discord.AuditLogAction.role_create and entry.target:
        track["roles"].append(entry.target.id)
    elif action == discord.AuditLogAction.webhook_create and entry.target:
        track["webhooks"].append(entry.target.id)

    def alert(title, desc):
        e = discord.Embed(title=title, description=desc, color=0xFF0000,
                          timestamp=discord.utils.utcnow())
        e.set_footer(text=f"Digit Anti-Nuke v{VER}")
        return e

    async def handle(action_key, title, reason):
        if over_threshold(uid, action_key, is_bot=is_bot_acct):
            member = guild.get_member(uid)
            tag = f"BOT {user}" if is_bot_acct else str(user)
            e = alert(
                f"ANTI-NUKE: {title}",
                f"**{tag}** (`{uid}`) triggered **{action_key.replace('_', ' ')}** threshold.\n"
                f"Banning and reversing all changes NOW."
            )
            # fire everything at once, don't await separately
            await asyncio.gather(
                log(guild, e),
                nuke_punishment(guild, member or user, reason),
                return_exceptions=True
            )

    if   action == discord.AuditLogAction.ban:
        await handle("ban",            "Mass Ban",         "mass banning members")
    elif action == discord.AuditLogAction.kick:
        await handle("kick",           "Mass Kick",        "mass kicking members")
    elif action == discord.AuditLogAction.channel_delete:
        await handle("channel_delete", "Mass Channel Del", "mass deleting channels")
    elif action == discord.AuditLogAction.channel_create:
        await handle("channel_create", "Mass Channel Create", "mass creating channels")
    elif action == discord.AuditLogAction.role_delete:
        await handle("role_delete",    "Mass Role Del",    "mass deleting roles")
    elif action == discord.AuditLogAction.role_create:
        await handle("role_create",    "Mass Role Create", "mass creating roles")
    elif action == discord.AuditLogAction.webhook_create:
        await handle("webhook_create", "Webhook Create",   "creating webhooks (possible token grab)")
    elif action == discord.AuditLogAction.member_prune:
        member = guild.get_member(uid)
        e = alert("Mass Member Prune", f"**{user}** (`{uid}`) pruned members.")
        await asyncio.gather(
            log(guild, e),
            nuke_punishment(guild, member or user, "mass member prune"),
            return_exceptions=True
        )
    elif action == discord.AuditLogAction.role_update:
        after = getattr(getattr(entry.changes, "after", None), "permissions", None)
        if after and after.administrator:
            e = discord.Embed(
                title="ALERT: Admin Perm Added to Role",
                description=f"**{user}** gave Administrator to role `{entry.target}`.\nCheck this NOW.",
                color=0xFF8C00, timestamp=discord.utils.utcnow()
            )
            await log(guild, e)
    elif action == discord.AuditLogAction.bot_add:
        e = discord.Embed(
            title="Bot Added to Server",
            description=f"**{user}** added a bot.",
            color=0x3498DB, timestamp=discord.utils.utcnow()
        )
        if entry.target:
            e.add_field(name="Bot", value=f"{entry.target} (`{entry.target.id}`)")
        await log(guild, e)
    elif action == discord.AuditLogAction.guild_update:
        e = discord.Embed(
            title="Server Settings Changed",
            description=f"**{user}** modified server settings.",
            color=0xF39C12, timestamp=discord.utils.utcnow()
        )
        await log(guild, e)

# ====================================================================
# ANTI-RAID -- MEMBER JOIN
# ====================================================================

def looks_like_raid_bot(member):
    # default avatar + account age < 3 days + numeric-ish name
    age = (discord.utils.utcnow() - member.created_at).days
    name = member.name.lower()
    generic_pattern = bool(re.search(r"\d{4,}", name) or re.search(r"^user\d+", name))
    default_av = member.display_avatar == member.default_avatar
    return age < 3 and (default_av or generic_pattern)

@bot.event
async def on_member_join(member):
    guild = member.guild
    cfg   = gcfg(guild.id)

    # ---- AUTO-BAN CHECK (always first) --------------------------
    if member.id in cfg.get("autoban_list", []):
        tag, u = await fetch_user_tag(member.id)
        # Warning DM -- NOT "Nice try." (that's only for nukers)
        try:
            dm = discord.Embed(
                title=f"You were banned from {guild.name}",
                description=(
                    "You are on this server's ban list and are not permitted to join.\n"
                    "If you believe this is a mistake, contact the server staff."
                ),
                color=0xFF8C00
            )
            dm.set_footer(text=f"Digit v{VER}")
            await member.send(embed=dm)
        except: pass
        try:
            await guild.ban(member, reason="[Digit] Auto-Ban List", delete_message_days=0)
        except: pass
        e = discord.Embed(
            title="AUTO-BAN TRIGGERED",
            description=f"{tag} tried to join -- they are on the auto-ban list. Instantly banned.",
            color=0xFF0000, timestamp=discord.utils.utcnow()
        )
        e.add_field(name="User ID", value=f"`{member.id}`", inline=True)
        e.add_field(name="Account Age", value=f"{(discord.utils.utcnow() - member.created_at).days}d", inline=True)
        await log(guild, e)
        return
    # --------------------------------------------------------------

    if not cfg.get("antiraid_enabled", True): return

    now = time.time()

    # Track recent joiners
    _raid_log[guild.id]     = [t for t in _raid_log[guild.id] if now - t < RAID_WINDOW]
    _raid_members[guild.id] = [m for m in _raid_members[guild.id]
                                if (discord.utils.utcnow() - m.joined_at).total_seconds() < RAID_WINDOW
                                if m.joined_at]
    _raid_log[guild.id].append(now)
    _raid_members[guild.id].append(member)

    # Raid detection: mass join
    if len(_raid_log[guild.id]) >= RAID_THRESHOLD:
        recent = list(_raid_members[guild.id])
        _raid_log[guild.id].clear()
        _raid_members[guild.id].clear()

        # Detect if they look like raid bots
        bot_count = sum(1 for m in recent if looks_like_raid_bot(m))
        raid_type = "Bot Raid" if bot_count >= len(recent) // 2 else "Mass Raid"

        e = discord.Embed(
            title=f"RAID DETECTED -- {raid_type}",
            description=(
                f"**{len(recent)} accounts** joined in **{RAID_WINDOW}s**!\n"
                f"Suspected bots: **{bot_count}**\n"
                f"All channels locked. Run `,unlock` when safe."
            ),
            color=0xFF0000, timestamp=discord.utils.utcnow()
        )
        e.set_footer(text=f"Digit Anti-Raid v{VER}")

        # Lock and send nice try to raid members, ban obvious bots
        async def raid_response():
            await do_lockdown(guild, lock=True)
            await log(guild, e)
            for m in recent:
                if looks_like_raid_bot(m):
                    try:
                        await m.send("Nice try.")
                        await guild.ban(m, reason="[Digit] Raid bot detected", delete_message_days=1)
                    except: pass

        asyncio.create_task(raid_response())
        return

    # Joingate: quarantine if account is too new (only if joingate on)
    if cfg.get("joingate_enabled", False):
        age = (discord.utils.utcnow() - member.created_at).days
        min_age = cfg.get("min_account_age", 0)
        if min_age > 0 and age < min_age:
            try:
                dm = discord.Embed(
                    title=f"Access Denied -- {guild.name}",
                    description=f"Your account is **{age}d** old. Minimum required: **{min_age}d**.",
                    color=0xFF8C00
                )
                await member.send(embed=dm)
                await member.kick(reason=f"[Digit] Account too new ({age}d < {min_age}d)")
            except: pass

@bot.event
async def on_member_remove(member):
    e = discord.Embed(
        title="Member Left",
        description=f"**{member}** (`{member.id}`) left the server.",
        color=0x95A5A6, timestamp=discord.utils.utcnow()
    )
    e.set_thumbnail(url=member.display_avatar.url)
    await log(member.guild, e)

@bot.event
async def on_member_ban(guild, user):
    e = discord.Embed(
        title="Member Banned",
        description=f"**{user}** (`{user.id}`) was banned.",
        color=0xFF0000, timestamp=discord.utils.utcnow()
    )
    await log(guild, e)

@bot.event
async def on_member_unban(guild, user):
    e = discord.Embed(
        title="Member Unbanned",
        description=f"**{user}** (`{user.id}`) was unbanned.",
        color=0x00FF88, timestamp=discord.utils.utcnow()
    )
    await log(guild, e)

# ====================================================================
# ANTI-SPAM -- MESSAGE
# ====================================================================

@bot.event
async def on_message(message):
    if not message.guild or message.author.bot:
        await bot.process_commands(message); return
    if message.author.id in _whitelist:
        await bot.process_commands(message); return
    if not gcfg(message.guild.id).get("antispam_enabled", True):
        await bot.process_commands(message); return

    uid = message.author.id
    now = time.time()
    _spam_log[uid] = [t for t in _spam_log[uid] if now - t < SPAM_WINDOW]
    _spam_log[uid].append(now)

    if len(_spam_log[uid]) >= SPAM_COUNT:
        _spam_log[uid].clear()
        ok = await do_timeout(message.author, 10, "[Digit] Spam detected")
        try:
            await message.channel.purge(limit=15, check=lambda m: m.author == message.author)
        except: pass
        note = "timed out 10min" if ok else "could not mute (check bot role position)"
        await message.channel.send(
            f"{message.author.mention} flagged for spam -- {note}.", delete_after=8
        )
        e = discord.Embed(
            title="Spam -- Auto Action",
            description=f"**{message.author}** flagged for spam.\nAction: {note}",
            color=0xFF8C00
        )
        await log(message.guild, e)
        return

    # Mass mention
    if len(message.mentions) >= MENTION_MAX:
        ok = await do_timeout(message.author, 30, "[Digit] Mass mention")
        try: await message.delete()
        except: pass
        await message.channel.send(
            f"{message.author.mention} flagged for mass-mentioning -- timed out 30min.", delete_after=8
        )
        e = discord.Embed(
            title="Mass Mention -- Auto Action",
            description=f"**{message.author}** used {len(message.mentions)} mentions. Timed out 30min.",
            color=0xFF8C00
        )
        await log(message.guild, e)
        return

    # Invite link filter
    if any(k in message.content for k in ("discord.gg/", "discord.com/invite/")):
        if not message.author.guild_permissions.manage_messages:
            try:
                await message.delete()
                await message.channel.send(f"{message.author.mention} No invite links here.", delete_after=5)
            except: pass
            return

    await bot.process_commands(message)

@bot.event
async def on_message_edit(before, after):
    if not before.guild or before.author.bot: return
    if before.content == after.content: return
    e = discord.Embed(
        title="Message Edited",
        description=f"**{before.author}** edited a message in {before.channel.mention}",
        color=0x3498DB, timestamp=discord.utils.utcnow()
    )
    e.add_field(name="Before", value=before.content[:500] or "empty", inline=False)
    e.add_field(name="After",  value=after.content[:500] or "empty",  inline=False)
    e.add_field(name="Link",   value=f"[Jump]({after.jump_url})", inline=True)
    await log(before.guild, e)

@bot.event
async def on_message_delete(message):
    if not message.guild or message.author.bot: return
    e = discord.Embed(
        title="Message Deleted",
        description=f"**{message.author}**'s message in {message.channel.mention} was deleted.",
        color=0xE74C3C, timestamp=discord.utils.utcnow()
    )
    e.add_field(name="Content", value=message.content[:500] or "empty", inline=False)
    await log(message.guild, e)

# ====================================================================
# SETUP + BOT ACCESS COMMANDS
# ====================================================================

@bot.command(name="setup")
@ba_or_perm("administrator")
async def setup_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    scfg(ctx.guild.id, "log_channel",      ch.id)
    scfg(ctx.guild.id, "antinuke_enabled", True)
    scfg(ctx.guild.id, "antiraid_enabled", True)
    scfg(ctx.guild.id, "antispam_enabled", True)
    scfg(ctx.guild.id, "joingate_enabled", False)
    scfg(ctx.guild.id, "min_account_age",  0)

    e = discord.Embed(
        title="Digit Setup Complete",
        description=f"Log channel set to {ch.mention}\nAll protection modules active.",
        color=discord.Color.green()
    )
    e.add_field(name="Anti-Nuke", value="ON", inline=True)
    e.add_field(name="Anti-Raid", value="ON", inline=True)
    e.add_field(name="Anti-Spam", value="ON", inline=True)
    e.set_footer(text=f"Digit v{VER} | prefix: {PREFIX}")
    await ctx.send(embed=e)

@bot.command(name="botaccess")
@ba_only()
async def botaccess_cmd(ctx, member: discord.Member):
    cfg = gcfg(ctx.guild.id)
    admins = cfg.get("bot_admins", [])
    if member.id in admins:
        return await ctx.send(f"**{member}** already has bot access.")
    admins.append(member.id)
    scfg(ctx.guild.id, "bot_admins", admins)
    await ctx.send(f"**{member}** has been granted full bot access. They can now use all Digit commands.")
    e = discord.Embed(
        title="Bot Access Granted",
        description=f"**{member}** (`{member.id}`) was granted bot admin access by **{ctx.author}**.",
        color=0x00FF88, timestamp=discord.utils.utcnow()
    )
    await log(ctx.guild, e)

@bot.command(name="revokebotaccess", aliases=["rba"])
@ba_only()
async def revoke_botaccess_cmd(ctx, member: discord.Member):
    cfg = gcfg(ctx.guild.id)
    admins = cfg.get("bot_admins", [])
    if member.id not in admins:
        return await ctx.send(f"**{member}** doesn't have bot access.")
    admins.remove(member.id)
    scfg(ctx.guild.id, "bot_admins", admins)
    await ctx.send(f"Revoked bot access from **{member}**.")

@bot.command(name="listbotaccess", aliases=["lba"])
@ba_only()
async def list_botaccess_cmd(ctx):
    admins = gcfg(ctx.guild.id).get("bot_admins", [])
    if not admins:
        return await ctx.send("No bot admins configured.")
    lines = []
    for uid in admins:
        tag, _ = await fetch_user_tag(uid)
        lines.append(f"- {tag}")
    e = discord.Embed(title=f"Bot Admins -- {len(admins)}", description="\n".join(lines), color=discord.Color.blurple())
    await ctx.send(embed=e)

# ====================================================================
# SECURITY TOGGLE COMMANDS
# ====================================================================

@bot.command(name="antinuke")
@ba_or_perm("administrator")
async def antinuke_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s in ("on","off"):
        scfg(ctx.guild.id, "antinuke_enabled", s == "on")
        await ctx.send(f"Anti-Nuke {'**ON**' if s == 'on' else '**OFF** -- server is now vulnerable!'}")
    else:
        on = gcfg(ctx.guild.id).get("antinuke_enabled", True)
        await ctx.send(f"Anti-Nuke is {'**ON**' if on else '**OFF**'}.")

@bot.command(name="antiraid")
@ba_or_perm("administrator")
async def antiraid_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s in ("on","off"):
        scfg(ctx.guild.id, "antiraid_enabled", s == "on")
        await ctx.send(f"Anti-Raid {'**ON**' if s == 'on' else '**OFF**'}.")
    else:
        on = gcfg(ctx.guild.id).get("antiraid_enabled", True)
        await ctx.send(f"Anti-Raid is {'**ON**' if on else '**OFF**'}.")

@bot.command(name="antispam")
@ba_or_perm("administrator")
async def antispam_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s in ("on","off"):
        scfg(ctx.guild.id, "antispam_enabled", s == "on")
        await ctx.send(f"Anti-Spam {'**ON**' if s == 'on' else '**OFF**'}.")
    else:
        on = gcfg(ctx.guild.id).get("antispam_enabled", True)
        await ctx.send(f"Anti-Spam is {'**ON**' if on else '**OFF**'}.")

@bot.command(name="joingate")
@ba_or_perm("administrator")
async def joingate_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s in ("on","off"):
        scfg(ctx.guild.id, "joingate_enabled", s == "on")
        await ctx.send(f"Join Gate {'**ON**' if s == 'on' else '**OFF**'}.")
    else:
        on = gcfg(ctx.guild.id).get("joingate_enabled", False)
        await ctx.send(f"Join Gate is {'**ON**' if on else '**OFF**'}.")

@bot.command(name="setage")
@ba_or_perm("administrator")
async def setage_cmd(ctx, days: int):
    scfg(ctx.guild.id, "min_account_age", max(0, days))
    await ctx.send(f"Minimum account age set to **{days}d** (only enforced when join gate is ON).")

@bot.command(name="whitelist")
@ba_or_perm("administrator")
async def whitelist_cmd(ctx, member: discord.Member):
    _whitelist.add(member.id)
    await ctx.send(f"**{member}** whitelisted -- immune to auto-actions.")

@bot.command(name="unwhitelist")
@ba_or_perm("administrator")
async def unwhitelist_cmd(ctx, member: discord.Member):
    _whitelist.discard(member.id)
    await ctx.send(f"**{member}** removed from whitelist.")

@bot.command(name="whitelisted")
@ba_or_perm("administrator")
async def whitelisted_cmd(ctx):
    if not _whitelist:
        return await ctx.send("Whitelist is empty.")
    lines = []
    for uid in _whitelist:
        m = ctx.guild.get_member(uid)
        lines.append(f"- **{m}** (`{uid}`)" if m else f"- `{uid}` (not in server)")
    e = discord.Embed(title=f"Whitelisted Users -- {len(_whitelist)}", description="\n".join(lines), color=discord.Color.green())
    await ctx.send(embed=e)

@bot.command(name="lockdown")
@ba_or_perm("administrator")
async def lockdown_cmd(ctx):
    await do_lockdown(ctx.guild, lock=True)
    e = discord.Embed(title="SERVER LOCKED DOWN", description=f"All channels locked. Run `,unlock` to lift.", color=discord.Color.red())
    await ctx.send(embed=e)

@bot.command(name="unlock")
@ba_or_perm("administrator")
async def unlock_cmd(ctx):
    await do_lockdown(ctx.guild, lock=False)
    e = discord.Embed(title="Lockdown Lifted", description="Members can send messages again.", color=discord.Color.green())
    await ctx.send(embed=e)

@bot.command(name="channellock")
@ba_or_perm("manage_channels")
async def channellock_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    ow = ch.overwrites_for(ctx.guild.default_role)
    ow.send_messages = False
    await ch.set_permissions(ctx.guild.default_role, overwrite=ow, reason=f"Locked by {ctx.author}")
    await ctx.send(f"Locked {ch.mention}.")

@bot.command(name="channelunlock")
@ba_or_perm("manage_channels")
async def channelunlock_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    ow = ch.overwrites_for(ctx.guild.default_role)
    ow.send_messages = None
    await ch.set_permissions(ctx.guild.default_role, overwrite=ow, reason=f"Unlocked by {ctx.author}")
    await ctx.send(f"Unlocked {ch.mention}.")

@bot.command(name="quarantine")
@ba_or_perm("administrator")
async def quarantine_cmd(ctx, member: discord.Member, *, reason="Quarantined"):
    if member.id in _quarantined:
        return await ctx.send(f"**{member}** is already quarantined.")
    saved = [r for r in member.roles[1:]]
    _quarantined[member.id] = [r.id for r in saved]
    try:
        await member.remove_roles(*saved, reason=f"[Digit] Quarantine: {reason}")
    except: pass
    await ctx.send(f"**{member}** quarantined -- all roles removed.")
    modlog(ctx.guild.id, member.id, "quarantine", ctx.author, reason)

@bot.command(name="unquarantine")
@ba_or_perm("administrator")
async def unquarantine_cmd(ctx, member: discord.Member):
    if member.id not in _quarantined:
        return await ctx.send(f"**{member}** is not quarantined.")
    role_ids = _quarantined.pop(member.id)
    roles = [ctx.guild.get_role(r) for r in role_ids if ctx.guild.get_role(r)]
    if roles:
        try: await member.add_roles(*roles, reason="[Digit] Unquarantine")
        except: pass
    await ctx.send(f"**{member}** unquarantined -- roles restored.")

@bot.command(name="setlog")
@ba_or_perm("administrator")
async def setlog_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    scfg(ctx.guild.id, "log_channel", ch.id)
    await ctx.send(f"Log channel set to {ch.mention}.")

@bot.command(name="status")
@ba_or_perm("manage_guild")
async def status_cmd(ctx):
    cfg = gcfg(ctx.guild.id)
    ms  = round(bot.latency * 1000)
    up  = int(time.time() - _uptime)
    uh, um = divmod(up, 3600); um //= 60
    e = discord.Embed(
        title=f"Digit v{VER} -- Security Status",
        description=f"**{ctx.guild.name}**",
        color=discord.Color.blurple(), timestamp=discord.utils.utcnow()
    )
    e.add_field(name="Anti-Nuke",  value="ON" if cfg.get("antinuke_enabled", True)  else "OFF", inline=True)
    e.add_field(name="Anti-Raid",  value="ON" if cfg.get("antiraid_enabled", True)  else "OFF", inline=True)
    e.add_field(name="Anti-Spam",  value="ON" if cfg.get("antispam_enabled", True)  else "OFF", inline=True)
    e.add_field(name="Join Gate",  value="ON" if cfg.get("joingate_enabled", False) else "OFF", inline=True)
    e.add_field(name="Log Channel",value=f"<#{cfg.get('log_channel')}>" if cfg.get("log_channel") else "Not set", inline=True)
    e.add_field(name="Whitelist",  value=str(len(_whitelist)), inline=True)
    e.add_field(name="Auto-Bans",  value=str(len(cfg.get("autoban_list", []))), inline=True)
    e.add_field(name="Bot Admins", value=str(len(cfg.get("bot_admins", []))), inline=True)
    e.add_field(name="Latency",    value=f"{ms}ms", inline=True)
    e.add_field(name="Uptime",     value=f"{uh}h {um}m", inline=True)
    e.add_field(name="Thresholds (nuke)", value=f"Ban/Kick: 2 in 5s\nCh/Role del: 2 in 5s\nWebhook: 1 in 5s", inline=False)
    e.add_field(name="Thresholds (raid)", value=f"{RAID_THRESHOLD} joins in {RAID_WINDOW}s", inline=True)
    e.set_footer(text=f"Digit v{VER}")
    await ctx.send(embed=e)

# ====================================================================
# AUTO-BAN COMMANDS
# ====================================================================

@bot.command(name="setautoban")
@ba_or_perm("administrator")
async def setautoban_cmd(ctx, *, user_input: str):
    uid = parse_uid(user_input)
    if not uid:
        return await ctx.send("Provide a valid user ID or @mention. Example: `,setautoban {123456789012345678}`")
    if uid == bot.user.id: return await ctx.send("That's me...")
    if uid == ctx.author.id: return await ctx.send("You can't autoban yourself.")
    if uid in get_autoban(ctx.guild.id):
        return await ctx.send(f"`{uid}` is already on the auto-ban list.")
    add_autoban(ctx.guild.id, uid)
    tag, _ = await fetch_user_tag(uid)
    e = discord.Embed(
        title="Auto-Ban -- User Added",
        description=(
            f"{tag} added to the auto-ban list.\n\n"
            f"If they try to join **{ctx.guild.name}**, they will be:\n"
            f"- Instantly banned\n"
            f"- Warned via DM\n"
            f"- Logged\n\n"
            f"To remove: `,setunautoban {uid}`"
        ),
        color=discord.Color.red(), timestamp=discord.utils.utcnow()
    )
    e.set_footer(text=f"Added by {ctx.author}")
    await ctx.send(embed=e)
    await log(ctx.guild, e)

@bot.command(name="setunautoban")
@ba_or_perm("administrator")
async def setunautoban_cmd(ctx, *, user_input: str):
    uid = parse_uid(user_input)
    if not uid: return await ctx.send("Provide a valid user ID.")
    if uid not in get_autoban(ctx.guild.id):
        return await ctx.send(f"`{uid}` is not on the auto-ban list.")
    rm_autoban(ctx.guild.id, uid)
    tag, _ = await fetch_user_tag(uid)
    await ctx.send(f"{tag} removed from auto-ban list. They may join again.\n**Note:** If still server-banned, also run `,unban {uid}`.")

@bot.command(name="listautoban", aliases=["autobanlist", "abl"])
@ba_or_perm("manage_guild")
async def listautoban_cmd(ctx):
    lst = get_autoban(ctx.guild.id)
    if not lst:
        return await ctx.send("Auto-ban list is empty.")
    lines = []
    for uid in lst:
        tag, _ = await fetch_user_tag(uid)
        lines.append(f"- {tag}")
    e = discord.Embed(
        title=f"Auto-Ban List -- {len(lst)} user(s)",
        description="\n".join(lines),
        color=discord.Color.red()
    )
    await ctx.send(embed=e)

# ====================================================================
# MODERATION
# ====================================================================

@bot.command(name="ban")
@ba_or_perm("ban_members")
async def ban_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    if member.top_role >= ctx.author.top_role and not ctx.author.guild_permissions.administrator:
        return await ctx.send("Can't ban someone with an equal or higher role.")
    try: await member.send(f"You have been banned from **{ctx.guild.name}**.\nReason: {reason}")
    except: pass
    await member.ban(reason=f"{ctx.author}: {reason}", delete_message_days=1)
    e = discord.Embed(title="Banned", description=f"**{member}** banned.", color=discord.Color.red())
    e.add_field(name="Reason", value=reason); e.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=e)
    await log(ctx.guild, e)
    modlog(ctx.guild.id, member.id, "ban", ctx.author, reason)

@bot.command(name="unban")
@ba_or_perm("ban_members")
async def unban_cmd(ctx, *, user_id: int):
    try:
        user = await bot.fetch_user(user_id)
        await ctx.guild.unban(user, reason=f"Unbanned by {ctx.author}")
        await ctx.send(f"**{user}** unbanned.")
    except discord.NotFound:
        await ctx.send("That user isn't banned or doesn't exist.")

@bot.command(name="kick")
@ba_or_perm("kick_members")
async def kick_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    if member.top_role >= ctx.author.top_role and not ctx.author.guild_permissions.administrator:
        return await ctx.send("Can't kick someone with an equal or higher role.")
    try: await member.send(f"You were kicked from **{ctx.guild.name}**.\nReason: {reason}")
    except: pass
    await member.kick(reason=f"{ctx.author}: {reason}")
    e = discord.Embed(title="Kicked", description=f"**{member}** kicked.", color=discord.Color.orange())
    e.add_field(name="Reason", value=reason); e.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=e); await log(ctx.guild, e)
    modlog(ctx.guild.id, member.id, "kick", ctx.author, reason)

@bot.command(name="softban")
@ba_or_perm("ban_members")
async def softban_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    await member.ban(reason=f"[Softban] {ctx.author}: {reason}", delete_message_days=7)
    await ctx.guild.unban(member, reason="Softban -- unban")
    await ctx.send(f"**{member}** soft-banned (messages deleted, then unbanned).")
    modlog(ctx.guild.id, member.id, "softban", ctx.author, reason)

@bot.command(name="tempban")
@ba_or_perm("ban_members")
async def tempban_cmd(ctx, member: discord.Member, duration: str = "1h", *, reason="No reason"):
    secs = parse_duration(duration)
    if not secs: return await ctx.send("Invalid duration. Use formats like `10m`, `2h`, `1d`.")
    try: await member.send(f"You have been temporarily banned from **{ctx.guild.name}** for {duration}.\nReason: {reason}")
    except: pass
    await member.ban(reason=f"[TempBan {duration}] {ctx.author}: {reason}", delete_message_days=1)
    await ctx.send(f"**{member}** temp-banned for **{duration}**.")
    modlog(ctx.guild.id, member.id, f"tempban ({duration})", ctx.author, reason)
    await asyncio.sleep(secs)
    try:
        await ctx.guild.unban(member, reason=f"Tempban expired ({duration})")
    except: pass

@bot.command(name="mute")
@ba_or_perm("moderate_members")
async def mute_cmd(ctx, member: discord.Member, duration: str = "10m", *, reason="No reason"):
    secs = parse_duration(duration)
    if not secs: return await ctx.send("Invalid duration. Use `10m`, `2h`, `1d`, etc.")
    ok = await do_timeout(member, secs // 60, f"[Digit] {ctx.author}: {reason}")
    if ok:
        await ctx.send(f"**{member}** muted for **{duration}**. Reason: {reason}")
        modlog(ctx.guild.id, member.id, f"mute ({duration})", ctx.author, reason)
    else:
        await ctx.send(f"Failed to mute **{member}**. Make sure my role is above theirs and I have Moderate Members permission.")

@bot.command(name="unmute")
@ba_or_perm("moderate_members")
async def unmute_cmd(ctx, member: discord.Member):
    try:
        await member.timeout(None)
        await ctx.send(f"**{member}** unmuted.")
    except Exception as e:
        await ctx.send(f"Failed: {e}")

@bot.command(name="warn")
@ba_or_perm("manage_messages")
async def warn_cmd(ctx, member: discord.Member, *, reason="No reason"):
    _warns[member.id].append({"reason": reason, "mod": str(ctx.author), "time": discord.utils.utcnow().isoformat()})
    count = len(_warns[member.id])
    e = discord.Embed(title="Member Warned", description=f"**{member}** warned. `{count}` total.", color=discord.Color.yellow())
    e.add_field(name="Reason", value=reason); e.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=e)
    try: await member.send(f"You were warned in **{ctx.guild.name}**.\nReason: {reason}\nTotal warnings: {count}")
    except: pass
    modlog(ctx.guild.id, member.id, "warn", ctx.author, reason)
    if count >= 5: await ctx.send(f"**{member}** has **{count} warnings**. Consider taking action.")

@bot.command(name="warnings")
@ba_or_perm("manage_messages")
async def warnings_cmd(ctx, member: discord.Member):
    ws = _warns.get(member.id, [])
    if not ws: return await ctx.send(f"**{member}** has no warnings.")
    e = discord.Embed(title=f"Warnings -- {member}", color=discord.Color.yellow())
    for i, w in enumerate(ws, 1):
        e.add_field(name=f"#{i} -- {w['mod']}", value=w['reason'], inline=False)
    await ctx.send(embed=e)

@bot.command(name="clearwarns")
@ba_or_perm("administrator")
async def clearwarns_cmd(ctx, member: discord.Member):
    _warns[member.id].clear()
    await ctx.send(f"Cleared all warnings for **{member}**.")

@bot.command(name="delwarn")
@ba_or_perm("manage_messages")
async def delwarn_cmd(ctx, member: discord.Member, index: int):
    ws = _warns.get(member.id, [])
    if not ws or index < 1 or index > len(ws):
        return await ctx.send("Invalid warning index.")
    removed = ws.pop(index - 1)
    await ctx.send(f"Removed warning #{index} from **{member}**: {removed['reason']}")

@bot.command(name="note")
@ba_or_perm("manage_messages")
async def note_cmd(ctx, member: discord.Member, *, text: str):
    _notes_db[f"{ctx.guild.id}:{member.id}"].append({"note": text, "by": str(ctx.author), "time": discord.utils.utcnow().isoformat()})
    await ctx.send(f"Note added for **{member}**.")

@bot.command(name="notes")
@ba_or_perm("manage_messages")
async def notes_cmd(ctx, member: discord.Member):
    ns = _notes_db.get(f"{ctx.guild.id}:{member.id}", [])
    if not ns: return await ctx.send(f"No notes for **{member}**.")
    e = discord.Embed(title=f"Notes -- {member}", color=discord.Color.blurple())
    for i, n in enumerate(ns, 1):
        e.add_field(name=f"#{i} by {n['by']}", value=n['note'], inline=False)
    await ctx.send(embed=e)

@bot.command(name="clearnotes")
@ba_or_perm("administrator")
async def clearnotes_cmd(ctx, member: discord.Member):
    _notes_db.pop(f"{ctx.guild.id}:{member.id}", None)
    await ctx.send(f"Notes cleared for **{member}**.")

@bot.command(name="modlogs")
@ba_or_perm("manage_messages")
async def modlogs_cmd(ctx, member: discord.Member):
    history = _mod_history.get(f"{ctx.guild.id}:{member.id}", [])
    if not history: return await ctx.send(f"No mod history for **{member}**.")
    e = discord.Embed(title=f"Mod History -- {member}", color=discord.Color.blurple())
    for entry in history[-10:]:
        e.add_field(name=f"{entry['action']} by {entry['mod']}", value=entry['reason'], inline=False)
    await ctx.send(embed=e)

@bot.command(name="clearmodlogs")
@ba_or_perm("administrator")
async def clearmodlogs_cmd(ctx, member: discord.Member):
    _mod_history.pop(f"{ctx.guild.id}:{member.id}", None)
    await ctx.send(f"Mod logs cleared for **{member}**.")

@bot.command(name="nick")
@ba_or_perm("manage_nicknames")
async def nick_cmd(ctx, member: discord.Member, *, name=None):
    old = member.display_name
    await member.edit(nick=name)
    await ctx.send(f"Changed **{old}**'s nickname to **{name or member.name}**.")

@bot.command(name="resetnick")
@ba_or_perm("manage_nicknames")
async def resetnick_cmd(ctx, member: discord.Member):
    await member.edit(nick=None)
    await ctx.send(f"Reset **{member.name}**'s nickname.")

@bot.command(name="deafen")
@ba_or_perm("deafen_members")
async def deafen_cmd(ctx, member: discord.Member, *, reason="No reason"):
    await member.edit(deafen=True, reason=reason)
    await ctx.send(f"**{member}** deafened.")

@bot.command(name="undeafen")
@ba_or_perm("deafen_members")
async def undeafen_cmd(ctx, member: discord.Member):
    await member.edit(deafen=False)
    await ctx.send(f"**{member}** undeafened.")

@bot.command(name="voicekick")
@ba_or_perm("move_members")
async def voicekick_cmd(ctx, member: discord.Member):
    if not member.voice:
        return await ctx.send(f"**{member}** is not in a voice channel.")
    await member.edit(voice_channel=None)
    await ctx.send(f"**{member}** disconnected from voice.")

@bot.command(name="voicemove")
@ba_or_perm("move_members")
async def voicemove_cmd(ctx, member: discord.Member, channel: discord.VoiceChannel):
    if not member.voice:
        return await ctx.send(f"**{member}** is not in a voice channel.")
    await member.move_to(channel)
    await ctx.send(f"Moved **{member}** to **{channel.name}**.")

@bot.command(name="announce")
@ba_or_perm("manage_messages")
async def announce_cmd(ctx, channel: discord.TextChannel = None, *, text: str):
    ch = channel or ctx.channel
    e = discord.Embed(description=text, color=discord.Color.blurple(), timestamp=discord.utils.utcnow())
    e.set_footer(text=f"Announced by {ctx.author}")
    try: await ctx.message.delete()
    except: pass
    await ch.send(embed=e)

@bot.command(name="dm")
@ba_or_perm("manage_messages")
async def dm_cmd(ctx, member: discord.Member, *, msg: str):
    try:
        await member.send(f"**Message from {ctx.guild.name} staff:**\n{msg}")
        await ctx.send(f"DM sent to **{member}**.")
    except: await ctx.send(f"Could not DM **{member}**.")

@bot.command(name="massban")
@ba_or_perm("administrator")
async def massban_cmd(ctx, *, ids: str):
    uid_list = [int(x.strip()) for x in ids.replace(",", " ").split() if x.strip().isdigit()]
    if not uid_list: return await ctx.send("Provide user IDs separated by spaces or commas.")
    msg = await ctx.send(f"Banning {len(uid_list)} users...")
    success = 0
    for uid in uid_list:
        try:
            u = await bot.fetch_user(uid)
            await ctx.guild.ban(u, reason=f"[Digit] Mass ban by {ctx.author}", delete_message_days=1)
            success += 1
        except: pass
    await msg.edit(content=f"Done. Banned **{success}/{len(uid_list)}** users.")

# ====================================================================
# PURGE
# ====================================================================

@bot.command(name="purge", aliases=["clear"])
@ba_or_perm("manage_messages")
async def purge_cmd(ctx, amount: int = 10):
    if amount < 1: return await ctx.send("Amount must be at least 1.", delete_after=4)
    try: await ctx.message.delete()
    except: pass
    # No cap -- discord.py handles batching internally
    deleted = await ctx.channel.purge(limit=amount)
    m = await ctx.send(f"Deleted **{len(deleted)}** messages.")
    await asyncio.sleep(4)
    try: await m.delete()
    except: pass

@bot.command(name="purgeuser")
@ba_or_perm("manage_messages")
async def purgeuser_cmd(ctx, member: discord.Member, amount: int = 50):
    try: await ctx.message.delete()
    except: pass
    deleted = await ctx.channel.purge(limit=amount * 3, check=lambda m: m.author == member)
    m = await ctx.send(f"Deleted **{len(deleted)}** messages from **{member}**.")
    await asyncio.sleep(4)
    try: await m.delete()
    except: pass

@bot.command(name="purgebotz")
@ba_or_perm("manage_messages")
async def purgebotz_cmd(ctx, amount: int = 50):
    try: await ctx.message.delete()
    except: pass
    deleted = await ctx.channel.purge(limit=amount * 3, check=lambda m: m.author.bot)
    m = await ctx.send(f"Deleted **{len(deleted)}** bot messages.")
    await asyncio.sleep(4)
    try: await m.delete()
    except: pass

@bot.command(name="purgeuntil")
@ba_or_perm("manage_messages")
async def purgeuntil_cmd(ctx, message_id: int):
    try: await ctx.message.delete()
    except: pass
    target = discord.Object(id=message_id)
    deleted = await ctx.channel.purge(limit=500, after=target)
    m = await ctx.send(f"Deleted **{len(deleted)}** messages after that point.")
    await asyncio.sleep(4)
    try: await m.delete()
    except: pass

@bot.command(name="slowmode")
@ba_or_perm("manage_channels")
async def slowmode_cmd(ctx, seconds: int = 0):
    await ctx.channel.edit(slowmode_delay=seconds)
    await ctx.send(f"Slowmode {'disabled' if seconds == 0 else f'set to **{seconds}s**'}.")

# ====================================================================
# ROLE COMMANDS
# ====================================================================

@bot.command(name="role")
@ba_or_perm("manage_roles")
async def role_cmd(ctx, action: str, member: discord.Member, role: discord.Role):
    action = action.lower()
    if action == "add":
        await member.add_roles(role, reason=f"{ctx.author}")
        await ctx.send(f"Gave **{role.name}** to **{member}**.")
    elif action == "remove":
        await member.remove_roles(role, reason=f"{ctx.author}")
        await ctx.send(f"Removed **{role.name}** from **{member}**.")
    else:
        await ctx.send("Use `,role add` or `,role remove`.")

@bot.command(name="roleall")
@ba_or_perm("manage_roles")
async def roleall_cmd(ctx, role: discord.Role):
    msg = await ctx.send(f"Adding **{role.name}** to all members...")
    count = 0
    for m in ctx.guild.members:
        if role not in m.roles:
            try: await m.add_roles(role); count += 1
            except: pass
    await msg.edit(content=f"Done. Added **{role.name}** to **{count}** members.")

@bot.command(name="rolerall")
@ba_or_perm("manage_roles")
async def rolerall_cmd(ctx, role: discord.Role):
    msg = await ctx.send(f"Removing **{role.name}** from all members...")
    count = 0
    for m in ctx.guild.members:
        if role in m.roles:
            try: await m.remove_roles(role); count += 1
            except: pass
    await msg.edit(content=f"Done. Removed **{role.name}** from **{count}** members.")

@bot.command(name="createrole")
@ba_or_perm("manage_roles")
async def createrole_cmd(ctx, name: str, color: str = "000000"):
    try:
        hex_color = int(color.lstrip("#"), 16)
        role = await ctx.guild.create_role(name=name, color=discord.Color(hex_color), reason=f"{ctx.author}")
        await ctx.send(f"Created role **{role.name}**.")
    except Exception as e:
        await ctx.send(f"Failed: {e}")

@bot.command(name="deleterole")
@ba_or_perm("manage_roles")
async def deleterole_cmd(ctx, role: discord.Role):
    await role.delete(reason=f"{ctx.author}")
    await ctx.send(f"Deleted role **{role.name}**.")

@bot.command(name="rolecolor")
@ba_or_perm("manage_roles")
async def rolecolor_cmd(ctx, role: discord.Role, color: str):
    try:
        hex_color = int(color.lstrip("#"), 16)
        await role.edit(color=discord.Color(hex_color))
        await ctx.send(f"Changed **{role.name}** color to `#{color.lstrip('#').upper()}`.")
    except Exception as e:
        await ctx.send(f"Failed: {e}")

@bot.command(name="rolehoist")
@ba_or_perm("manage_roles")
async def rolehoist_cmd(ctx, role: discord.Role):
    await role.edit(hoist=not role.hoist)
    await ctx.send(f"**{role.name}** hoist toggled to `{not role.hoist}`.")

@bot.command(name="rolemention")
@ba_or_perm("manage_roles")
async def rolemention_cmd(ctx, role: discord.Role):
    await role.edit(mentionable=not role.mentionable)
    await ctx.send(f"**{role.name}** mentionable toggled to `{not role.mentionable}`.")

@bot.command(name="roleinfo")
async def roleinfo_cmd(ctx, role: discord.Role):
    e = discord.Embed(title=f"Role -- {role.name}", color=role.color, timestamp=discord.utils.utcnow())
    e.add_field(name="ID",          value=role.id, inline=True)
    e.add_field(name="Color",       value=str(role.color), inline=True)
    e.add_field(name="Members",     value=len(role.members), inline=True)
    e.add_field(name="Mentionable", value=role.mentionable, inline=True)
    e.add_field(name="Hoisted",     value=role.hoist, inline=True)
    e.add_field(name="Position",    value=role.position, inline=True)
    e.add_field(name="Created",     value=f"<t:{int(role.created_at.timestamp())}:R>", inline=True)
    await ctx.send(embed=e)

@bot.command(name="rolelist")
async def rolelist_cmd(ctx):
    roles = [r for r in ctx.guild.roles if r.name != "@everyone"]
    roles.reverse()
    text = "\n".join(f"{r.mention} -- {len(r.members)} members" for r in roles[:30])
    e = discord.Embed(title=f"Roles -- {len(roles)}", description=text, color=discord.Color.blurple())
    if len(roles) > 30: e.set_footer(text=f"Showing top 30 of {len(roles)}")
    await ctx.send(embed=e)

@bot.command(name="inrole")
async def inrole_cmd(ctx, role: discord.Role):
    members = role.members
    if not members: return await ctx.send(f"No members have **{role.name}**.")
    text = ", ".join(str(m) for m in members[:30])
    e = discord.Embed(title=f"Members with {role.name} -- {len(members)}", description=text, color=role.color)
    if len(members) > 30: e.set_footer(text=f"Showing first 30 of {len(members)}")
    await ctx.send(embed=e)

@bot.command(name="roleperms")
async def roleperms_cmd(ctx, role: discord.Role):
    perms = [p for p, val in role.permissions if val]
    e = discord.Embed(title=f"Permissions -- {role.name}", description=", ".join(perms) or "None", color=role.color)
    await ctx.send(embed=e)

# ====================================================================
# CHANNEL COMMANDS
# ====================================================================

@bot.command(name="createchannel", aliases=["cc"])
@ba_or_perm("manage_channels")
async def createchannel_cmd(ctx, name: str, ch_type: str = "text"):
    if ch_type == "voice":
        ch = await ctx.guild.create_voice_channel(name, reason=f"{ctx.author}")
    elif ch_type == "category":
        ch = await ctx.guild.create_category(name, reason=f"{ctx.author}")
    else:
        ch = await ctx.guild.create_text_channel(name, reason=f"{ctx.author}")
    await ctx.send(f"Created {ch_type} channel **{name}** ({ch.mention}).")

@bot.command(name="deletechannel", aliases=["dc"])
@ba_or_perm("manage_channels")
async def deletechannel_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    name = ch.name
    await ch.delete(reason=f"{ctx.author}")
    if ch != ctx.channel:
        await ctx.send(f"Deleted channel **#{name}**.")

@bot.command(name="channelinfo", aliases=["chinfo"])
async def channelinfo_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    e = discord.Embed(title=f"Channel -- #{ch.name}", color=discord.Color.blurple())
    e.add_field(name="ID",       value=ch.id, inline=True)
    e.add_field(name="Topic",    value=ch.topic or "None", inline=True)
    e.add_field(name="NSFW",     value=ch.is_nsfw(), inline=True)
    e.add_field(name="Slowmode", value=f"{ch.slowmode_delay}s", inline=True)
    e.add_field(name="Created",  value=f"<t:{int(ch.created_at.timestamp())}:R>", inline=True)
    e.add_field(name="Category", value=ch.category.name if ch.category else "None", inline=True)
    await ctx.send(embed=e)

@bot.command(name="channeltopic")
@ba_or_perm("manage_channels")
async def channeltopic_cmd(ctx, channel: discord.TextChannel = None, *, topic: str = ""):
    ch = channel or ctx.channel
    await ch.edit(topic=topic)
    await ctx.send(f"Topic set for {ch.mention}.")

@bot.command(name="channelname")
@ba_or_perm("manage_channels")
async def channelname_cmd(ctx, channel: discord.TextChannel, *, name: str):
    old = channel.name
    await channel.edit(name=name)
    await ctx.send(f"Renamed **#{old}** to **#{name}**.")

@bot.command(name="clonechannel")
@ba_or_perm("manage_channels")
async def clonechannel_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    new_ch = await ch.clone(name=f"{ch.name}-clone", reason=f"{ctx.author}")
    await ctx.send(f"Cloned {ch.mention} to {new_ch.mention}.")

@bot.command(name="nsfw")
@ba_or_perm("manage_channels")
async def nsfw_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    await ch.edit(nsfw=not ch.is_nsfw())
    await ctx.send(f"NSFW toggled {'ON' if not ch.is_nsfw() else 'OFF'} for {ch.mention}.")

@bot.command(name="sendmsg")
@ba_or_perm("manage_messages")
async def sendmsg_cmd(ctx, channel: discord.TextChannel, *, msg: str):
    try: await ctx.message.delete()
    except: pass
    await channel.send(msg)

# ====================================================================
# SERVER INFO
# ====================================================================

@bot.command(name="serverinfo", aliases=["si"])
async def serverinfo_cmd(ctx):
    g = ctx.guild
    e = discord.Embed(title=g.name, color=discord.Color.blurple(), timestamp=discord.utils.utcnow())
    if g.icon: e.set_thumbnail(url=g.icon.url)
    e.add_field(name="Owner",    value=g.owner.mention if g.owner else "?", inline=True)
    e.add_field(name="Members",  value=g.member_count, inline=True)
    e.add_field(name="Channels", value=len(g.channels), inline=True)
    e.add_field(name="Roles",    value=len(g.roles), inline=True)
    e.add_field(name="Boosts",   value=g.premium_subscription_count, inline=True)
    e.add_field(name="Level",    value=g.premium_tier, inline=True)
    e.add_field(name="Created",  value=f"<t:{int(g.created_at.timestamp())}:R>", inline=True)
    e.add_field(name="Verification", value=str(g.verification_level), inline=True)
    e.set_footer(text=f"ID: {g.id}")
    await ctx.send(embed=e)

@bot.command(name="membercount", aliases=["mc"])
async def membercount_cmd(ctx):
    g = ctx.guild
    bots    = sum(1 for m in g.members if m.bot)
    humans  = g.member_count - bots
    online  = sum(1 for m in g.members if m.status != discord.Status.offline)
    e = discord.Embed(title=f"Member Count -- {g.name}", color=discord.Color.blurple())
    e.add_field(name="Total",  value=g.member_count, inline=True)
    e.add_field(name="Humans", value=humans,          inline=True)
    e.add_field(name="Bots",   value=bots,            inline=True)
    e.add_field(name="Online", value=online,           inline=True)
    await ctx.send(embed=e)

@bot.command(name="boosts")
async def boosts_cmd(ctx):
    g = ctx.guild
    boosters = sorted(g.premium_subscribers, key=lambda m: m.premium_since or discord.utils.utcnow())
    e = discord.Embed(title=f"Boosts -- {g.name}", description=f"Level **{g.premium_tier}** | **{g.premium_subscription_count}** boosts", color=0xFF73FA)
    if boosters:
        e.add_field(name=f"Boosters ({len(boosters)})", value="\n".join(str(m) for m in boosters[:15]) or "None", inline=False)
    await ctx.send(embed=e)

@bot.command(name="emojis")
async def emojis_cmd(ctx):
    emojis = ctx.guild.emojis
    if not emojis: return await ctx.send("This server has no custom emojis.")
    chunks = [emojis[i:i+20] for i in range(0, len(emojis), 20)]
    e = discord.Embed(title=f"Emojis -- {len(emojis)}", description=" ".join(str(em) for em in chunks[0]), color=discord.Color.blurple())
    await ctx.send(embed=e)

@bot.command(name="servericon")
async def servericon_cmd(ctx):
    if not ctx.guild.icon: return await ctx.send("No server icon set.")
    e = discord.Embed(title=f"{ctx.guild.name} Icon", color=discord.Color.blurple())
    e.set_image(url=ctx.guild.icon.url)
    await ctx.send(embed=e)

@bot.command(name="invites")
@ba_or_perm("manage_guild")
async def invites_cmd(ctx):
    invs = await ctx.guild.invites()
    if not invs: return await ctx.send("No active invites.")
    e = discord.Embed(title=f"Invites -- {len(invs)}", color=discord.Color.blurple())
    for inv in invs[:10]:
        e.add_field(name=inv.code, value=f"By {inv.inviter} | {inv.uses} uses | expires: {'never' if not inv.max_age else f'{inv.max_age}s'}", inline=False)
    await ctx.send(embed=e)

@bot.command(name="addmoji")
@ba_or_perm("manage_emojis_and_stickers")
async def addmoji_cmd(ctx, name: str, url: str):
    async with aiohttp.ClientSession() as s:
        async with s.get(url) as r:
            if r.status != 200: return await ctx.send("Couldn't fetch that image.")
            data = await r.read()
    emoji = await ctx.guild.create_custom_emoji(name=name, image=data, reason=f"{ctx.author}")
    await ctx.send(f"Added emoji {emoji}.")

@bot.command(name="steal")
@ba_or_perm("manage_emojis_and_stickers")
async def steal_cmd(ctx, emoji_str: str, name: str = None):
    m = re.match(r"<a?:(\w+):(\d+)>", emoji_str)
    if not m: return await ctx.send("Provide a custom emoji from another server.")
    ename, eid = m.group(1), m.group(2)
    ext = "gif" if emoji_str.startswith("<a") else "png"
    url = f"https://cdn.discordapp.com/emojis/{eid}.{ext}"
    async with aiohttp.ClientSession() as s:
        async with s.get(url) as r:
            data = await r.read()
    new = await ctx.guild.create_custom_emoji(name=name or ename, image=data, reason=f"Stolen by {ctx.author}")
    await ctx.send(f"Stolen! {new}")

@bot.command(name="setverification")
@ba_or_perm("manage_guild")
async def setverification_cmd(ctx, level: str):
    levels = {"none": 0, "low": 1, "medium": 2, "high": 3, "highest": 4}
    lvl = levels.get(level.lower())
    if lvl is None: return await ctx.send(f"Valid levels: {', '.join(levels.keys())}")
    await ctx.guild.edit(verification_level=discord.VerificationLevel(lvl))
    await ctx.send(f"Verification level set to **{level}**.")

# ====================================================================
# USER INFO
# ====================================================================

@bot.command(name="userinfo", aliases=["whois"])
async def userinfo_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    age = (discord.utils.utcnow() - m.created_at).days
    e = discord.Embed(title=str(m), color=m.color, timestamp=discord.utils.utcnow())
    e.set_thumbnail(url=m.display_avatar.url)
    e.add_field(name="ID",       value=m.id, inline=True)
    e.add_field(name="Nickname", value=m.display_name, inline=True)
    e.add_field(name="Bot",      value="Yes" if m.bot else "No", inline=True)
    e.add_field(name="Created",  value=f"<t:{int(m.created_at.timestamp())}:R>", inline=True)
    e.add_field(name="Joined",   value=f"<t:{int(m.joined_at.timestamp())}:R>", inline=True)
    e.add_field(name="Acc Age",  value=f"{age}d", inline=True)
    roles = [r.mention for r in m.roles[1:]]
    if roles: e.add_field(name=f"Roles ({len(roles)})", value=" ".join(roles[:8]) + ("..." if len(roles) > 8 else ""), inline=False)
    e.add_field(name="Warnings",  value=len(_warns.get(m.id, [])), inline=True)
    on_abl = m.id in get_autoban(ctx.guild.id)
    e.add_field(name="Auto-Ban",  value="YES" if on_abl else "No", inline=True)
    in_wl = m.id in _whitelist
    e.add_field(name="Whitelist", value="YES" if in_wl else "No", inline=True)
    e.set_footer(text="Digit")
    await ctx.send(embed=e)

@bot.command(name="avatar", aliases=["av"])
async def avatar_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    e = discord.Embed(title=f"{m.display_name}'s Avatar", color=discord.Color.blurple())
    e.set_image(url=m.display_avatar.url)
    e.add_field(name="Links", value=f"[PNG]({m.display_avatar.replace(format='png').url}) | [WEBP]({m.display_avatar.replace(format='webp').url})")
    await ctx.send(embed=e)

@bot.command(name="banner")
async def banner_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    user = await bot.fetch_user(m.id)
    if not user.banner: return await ctx.send(f"**{m}** has no banner.")
    e = discord.Embed(title=f"{m.display_name}'s Banner", color=discord.Color.blurple())
    e.set_image(url=user.banner.url)
    await ctx.send(embed=e)

@bot.command(name="perms")
async def perms_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    granted = [p for p, val in m.guild_permissions if val]
    e = discord.Embed(title=f"Permissions -- {m}", description=", ".join(granted) or "None", color=discord.Color.blurple())
    await ctx.send(embed=e)

@bot.command(name="joined")
async def joined_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    e = discord.Embed(
        title=f"Join Info -- {m}",
        description=f"Joined: <t:{int(m.joined_at.timestamp())}:F>\nAccount Created: <t:{int(m.created_at.timestamp())}:F>",
        color=discord.Color.blurple()
    )
    await ctx.send(embed=e)

@bot.command(name="botinfo")
async def botinfo_cmd(ctx):
    up = int(time.time() - _uptime)
    uh, rem = divmod(up, 3600); um, us = divmod(rem, 60)
    e = discord.Embed(title=f"Digit v{VER}", color=discord.Color.blurple())
    e.add_field(name="Servers",  value=len(bot.guilds), inline=True)
    e.add_field(name="Latency",  value=f"{round(bot.latency * 1000)}ms", inline=True)
    e.add_field(name="Uptime",   value=f"{uh}h {um}m {us}s", inline=True)
    e.add_field(name="Commands", value=len(bot.commands), inline=True)
    e.add_field(name="Prefix",   value=PREFIX, inline=True)
    e.set_footer(text="Digit -- Protection above all else")
    await ctx.send(embed=e)

# ====================================================================
# ROBLOX COMMANDS + UPDATE WATCHER
# ====================================================================

async def fetch_roblox_all():
    global _roblox_vers
    async with aiohttp.ClientSession() as session:
        for platform, info in ROBLOX_PLATFORMS.items():
            try:
                url = f"https://clientsettingscdn.roblox.com/v2/client-version/{info['api_key']}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        _roblox_vers[platform] = {
                            "version":  d.get("clientVersionUpload", "Unknown"),
                            "display":  d.get("version", "Unknown"),
                            "boot":     d.get("bootstrapperVersion", "Unknown"),
                        }
            except Exception as e:
                print(f"[roblox] {platform}: {e}")

async def send_roblox_update(platform, old_ver, new_data):
    info = ROBLOX_PLATFORMS.get(platform, {})
    now  = discord.utils.utcnow()
    for gid, cfg in _guild_cfg.items():
        if not cfg.get("roblox_alerts", False): continue
        cid = cfg.get("roblox_channel")
        if not cid: continue
        guild = bot.get_guild(int(gid))
        if not guild: continue
        ch = guild.get_channel(int(cid))
        if not ch: continue
        e = discord.Embed(
            title=f"Roblox {platform} -- NEW UPDATE",
            description=f"Roblox just released a new **{platform}** update!",
            color=0xFF0000, timestamp=now
        )
        e.add_field(name="Old Version",     value=old_ver,                       inline=True)
        e.add_field(name="New Version",     value=new_data.get("version", "?"),  inline=True)
        e.add_field(name="Internal Build",  value=new_data.get("version", "?"),  inline=True)
        e.add_field(name="Platform",        value=platform,                      inline=True)
        e.add_field(name="Update Time",     value=f"<t:{int(now.timestamp())}:F> (<t:{int(now.timestamp())}:R>)", inline=False)
        e.add_field(name="Download Link",   value=f"[Download {platform}]({info.get('dl', 'https://www.roblox.com')})", inline=False)
        if platform == "Windows":
            e.add_field(name="All Downloads", value=(
                f"[Windows]({ROBLOX_PLATFORMS['Windows']['dl']}) | "
                f"[Mac]({ROBLOX_PLATFORMS['Mac']['dl']}) | "
                f"[Android]({ROBLOX_PLATFORMS['Android']['dl']}) | "
                f"[iOS]({ROBLOX_PLATFORMS['iOS']['dl']}) | "
                f"[Studio]({ROBLOX_PLATFORMS['Studio']['dl']})"
            ), inline=False)
        e.set_footer(text=f"Digit Roblox Monitor v{VER}")
        try: await ch.send(embed=e)
        except: pass

@tasks.loop(minutes=5)
async def roblox_check():
    if not _roblox_vers:
        await fetch_roblox_all(); return
    old = {k: v.get("version") for k, v in _roblox_vers.items()}
    await fetch_roblox_all()
    for plat in ROBLOX_PLATFORMS:
        old_v = old.get(plat)
        new_v = _roblox_vers.get(plat, {}).get("version")
        if old_v and new_v and old_v != new_v:
            await send_roblox_update(plat, old_v, _roblox_vers[plat])

@roblox_check.before_loop
async def before_roblox():
    await bot.wait_until_ready()

@bot.command(name="robloxversion", aliases=["rbxver"])
async def robloxversion_cmd(ctx):
    if not _roblox_vers:
        msg = await ctx.send("Fetching Roblox versions...")
        await fetch_roblox_all()
        await msg.delete()
    e = discord.Embed(title="Roblox Version Info", color=0xFF0000, timestamp=discord.utils.utcnow())
    for plat, data in _roblox_vers.items():
        info = ROBLOX_PLATFORMS.get(plat, {})
        e.add_field(
            name=plat,
            value=f"Version: `{data.get('display', '?')}`\n[Download]({info.get('dl', 'https://roblox.com')})",
            inline=True
        )
    e.set_footer(text="Digit Roblox Monitor | Updated every 5 minutes")
    await ctx.send(embed=e)

@bot.command(name="robloxalert")
async def robloxalert_cmd(ctx):
    await robloxversion_cmd(ctx)

@bot.command(name="robloxstatus")
async def robloxstatus_cmd(ctx):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://status.roblox.com/api/v2/summary.json", timeout=aiohttp.ClientTimeout(total=10)) as r:
                data = await r.json()
        status = data.get("status", {})
        indicator = status.get("indicator", "unknown")
        desc = status.get("description", "Unknown")
        color = 0x00FF00 if indicator == "none" else 0xFF8C00 if indicator == "minor" else 0xFF0000
        e = discord.Embed(title="Roblox Status", description=f"**{desc}**", color=color)
        for comp in data.get("components", [])[:5]:
            e.add_field(name=comp.get("name", "?"), value=comp.get("status", "?").replace("_", " ").title(), inline=True)
        e.set_footer(text="status.roblox.com")
        await ctx.send(embed=e)
    except Exception as e:
        await ctx.send(f"Couldn't reach Roblox status API: {e}")

@bot.command(name="setrobloxchannel")
@ba_or_perm("administrator")
async def setrobloxchannel_cmd(ctx, channel: discord.TextChannel = None):
    ch = channel or ctx.channel
    scfg(ctx.guild.id, "roblox_channel", ch.id)
    await ctx.send(f"Roblox update alerts will be sent to {ch.mention}.")

@bot.command(name="robloxupdates")
@ba_or_perm("administrator")
async def robloxupdates_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s in ("on","off"):
        scfg(ctx.guild.id, "roblox_alerts", s == "on")
        await ctx.send(f"Roblox update alerts {'**ON**' if s == 'on' else '**OFF**'}.")
    else:
        on = gcfg(ctx.guild.id).get("roblox_alerts", False)
        await ctx.send(f"Roblox alerts: {'**ON**' if on else '**OFF**'}.")

@bot.command(name="robloxinfo")
async def robloxinfo_cmd(ctx, username: str):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post("https://users.roblox.com/v1/usernames/users",
                              json={"usernames": [username], "excludeBannedUsers": False},
                              timeout=aiohttp.ClientTimeout(total=10)) as r:
                data = await r.json()
            users = data.get("data", [])
            if not users: return await ctx.send(f"User **{username}** not found on Roblox.")
            uid = users[0]["id"]
            async with s.get(f"https://users.roblox.com/v1/users/{uid}", timeout=aiohttp.ClientTimeout(total=10)) as r2:
                udata = await r2.json()
        e = discord.Embed(title=udata.get("displayName", username), color=0xFF0000)
        e.add_field(name="Username",    value=udata.get("name", "?"), inline=True)
        e.add_field(name="User ID",     value=uid, inline=True)
        e.add_field(name="Created",     value=udata.get("created", "?")[:10], inline=True)
        e.add_field(name="Banned",      value="Yes" if udata.get("isBanned") else "No", inline=True)
        e.add_field(name="Description", value=(udata.get("description") or "No description")[:300], inline=False)
        e.add_field(name="Profile",     value=f"[View Profile](https://www.roblox.com/users/{uid}/profile)", inline=False)
        await ctx.send(embed=e)
    except Exception as ex:
        await ctx.send(f"Error: {ex}")

# ====================================================================
# FUN COMMANDS
# ====================================================================

@bot.command(name="ratio")
async def ratio_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    picks = [
        f"L + ratio + {m.mention} has been obliterated. No saves.",
        f"{m.mention} ratio'd into a different dimension. Fr fr.",
        f"{m.mention} L + ratio + didn't ask + cope + skill issue",
        f"The Digit Council has spoken: {m.mention} is hereby ratio'd. No appeals.",
        f"{m.mention} touched grass and STILL got ratio'd. Impressive.",
        f"Breaking news: {m.mention} ratio'd harder than a 56k modem.",
        f"{m.mention} just got ratio'd by a bot. Let that sink in.",
    ]
    await ctx.send(random.choice(picks))

@bot.command(name="iq")
async def iq_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    score = random.randint(1, 200)
    comment = (
        "A goldfish wants its braincell back."        if score < 40  else
        "Tried. A for effort. F for existing."        if score < 70  else
        "Average. Breathe through your nose."         if score < 100 else
        "Decent. You might survive the apocalypse."   if score < 130 else
        "Big brain. Consider world domination."        if score < 160 else
        "GALAXY BRAIN. Reality is cracking."
    )
    e = discord.Embed(title=f"IQ Test -- {m.display_name}", description=f"Score: **{score}**\n{comment}", color=discord.Color.purple())
    await ctx.send(embed=e)

@bot.command(name="roast")
@commands.cooldown(1, 10, commands.BucketType.user)
async def roast_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    roasts = [
        f"{m.mention} the reason shampoo has instructions.",
        f"{m.mention} I'd agree but we'd both be wrong.",
        f"{m.mention} human version of a 404 error.",
        f"{m.mention} even your spam folder ignores you.",
        f"{m.mention} software update nobody wanted but keeps appearing.",
        f"{m.mention} proof evolution takes lunch breaks.",
        f"{m.mention} participation trophy of this server.",
        f"{m.mention} WiFi password is probably 'password'. Isn't it.",
    ]
    await ctx.send(random.choice(roasts))

@bot.command(name="sus")
async def sus_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    lvl = random.randint(0, 100)
    verdict, color = (
        ("Clean. Probably.", discord.Color.green())   if lvl < 20 else
        ("A little sus. Watch them.", discord.Color.yellow()) if lvl < 50 else
        ("Very sus. Emergency meeting.", discord.Color.orange()) if lvl < 80 else
        ("MEGA SUS. VOTE OUT NOW.", discord.Color.red())
    )
    e = discord.Embed(title="Sus-O-Meter", description=f"**{m.display_name}** is **{lvl}% sus**\n{verdict}", color=color)
    await ctx.send(embed=e)

@bot.command(name="touchgrass", aliases=["grass"])
async def touchgrass_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    hrs = random.randint(1, 72)
    acts = ["touch grass", "see sunlight", "talk to a real human", "drink water", "pet a dog", "feel wind"]
    e = discord.Embed(
        title="Touch Grass Advisory",
        description=f"{m.mention} is **officially advised** to go **{random.choice(acts)}** for at least **{hrs} hours**.\nThis is not optional.",
        color=discord.Color.green()
    )
    await ctx.send(embed=e)

@bot.command(name="skill")
async def skill_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    lvl = random.randint(0, 100)
    thing = random.choice(["Trolling","Sleeping","Gaming","Being Delusional","Speedrunning mistakes","Being offline","Coping"])
    bar = "#" * (lvl // 10) + "." * (10 - lvl // 10)
    verdict = "GOAT" if lvl == 100 else "Decent" if lvl > 70 else "Mid" if lvl > 40 else "Uninstall"
    e = discord.Embed(title=f"Skill -- {m.display_name}", description=f"**{thing}**\n`[{bar}]` {lvl}/100 -- {verdict}", color=discord.Color.gold())
    await ctx.send(embed=e)

@bot.command(name="ship")
async def ship_cmd(ctx, m1: discord.Member, m2: discord.Member = None):
    m2 = m2 or ctx.author
    score = random.randint(0, 100)
    verdict = (
        "Zero chance." if score < 20 else "It's complicated." if score < 40 else
        "Potential." if score < 60 else "Ship it!" if score < 80 else "SOULMATES."
    )
    e = discord.Embed(title="Ship", description=f"**{m1.display_name}** x **{m2.display_name}**\n**{score}%** -- {verdict}", color=discord.Color.red())
    await ctx.send(embed=e)

@bot.command(name="coinflip", aliases=["flip"])
async def coinflip_cmd(ctx): await ctx.send(f"**{random.choice(['Heads', 'Tails'])}**!")

@bot.command(name="dice")
async def dice_cmd(ctx, sides: int = 6):
    if sides < 2: return await ctx.send("Need at least 2 sides.")
    await ctx.send(f"Rolled d{sides}: **{random.randint(1, sides)}**")

@bot.command(name="rate")
async def rate_cmd(ctx, *, thing: str):
    score = random.randint(0, 10)
    e = discord.Embed(title="Rating", description=f"**{thing}** -- **{score}/10**", color=discord.Color.gold())
    e.set_footer(text="Delete it." if score == 0 else "Frame it." if score == 10 else "")
    await ctx.send(embed=e)

@bot.command(name="rps")
async def rps_cmd(ctx, choice: str):
    icons = {"rock": "Rock", "paper": "Paper", "scissors": "Scissors"}
    c = choice.lower()
    if c not in icons: return await ctx.send("Pick rock, paper, or scissors.")
    b = random.choice(list(icons.keys()))
    if c == b: result = "Tie"
    elif (c, b) in [("rock","scissors"), ("paper","rock"), ("scissors","paper")]: result = "You win"
    else: result = "I win"
    color = discord.Color.yellow() if result == "Tie" else discord.Color.green() if result == "You win" else discord.Color.red()
    e = discord.Embed(title="Rock Paper Scissors", description=f"You: {icons[c]} vs Me: {icons[b]}\n**{result}!**", color=color)
    await ctx.send(embed=e)

@bot.command(name="8ball", aliases=["ask"])
async def eightball_cmd(ctx, *, question):
    answers = [
        "Definitely yes.", "Without a doubt.", "Signs point to yes.", "Most likely.",
        "Ask again later.", "Cannot predict now.", "Probably not.", "My reply is no.",
        "Don't count on it.", "ABSOLUTELY NOT. Delete yourself."
    ]
    e = discord.Embed(title="8-Ball", color=discord.Color.dark_blue())
    e.add_field(name="Question", value=question, inline=False)
    e.add_field(name="Answer",   value=random.choice(answers), inline=False)
    await ctx.send(embed=e)

@bot.command(name="hack")
@commands.cooldown(1, 30, commands.BucketType.channel)
async def hack_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    msg = await ctx.send(f"```[DIGIT] Initiating hack on {m.display_name}...```")
    await asyncio.sleep(1.2)
    await msg.edit(content=f"```[DIGIT] IP found: 127.0.0.1\n[DIGIT] Wait... that's literally their own PC```")
    await asyncio.sleep(1.5)
    await msg.edit(content=f"```[DIGIT] Files scanned:\n  > 1,457 memes (unsorted)\n  > 89 unfinished projects\n  > search history: 'how to be cool'\n  > minecraft screenshots (volume: embarrassing)```")
    await asyncio.sleep(1.8)
    await msg.edit(content=f"```[DIGIT] HACK COMPLETE.\n{m.display_name}:\n  - Ratio'd\n  - Exposed\n  - Skill issue confirmed\nNo actual hacking. You're welcome.```")

@bot.command(name="mock")
async def mock_cmd(ctx, *, text: str):
    result = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    await ctx.send(result)

@bot.command(name="say")
@ba_or_perm("manage_messages")
async def say_cmd(ctx, *, text: str):
    try: await ctx.message.delete()
    except: pass
    await ctx.send(text)

@bot.command(name="embed_msg", aliases=["embedmsg"])
@ba_or_perm("manage_messages")
async def embed_msg_cmd(ctx, *, text: str):
    try: await ctx.message.delete()
    except: pass
    parts = text.split("|", 1)
    title = parts[0].strip() if len(parts) > 1 else "Announcement"
    desc  = parts[1].strip() if len(parts) > 1 else parts[0].strip()
    e = discord.Embed(title=title, description=desc, color=discord.Color.blurple(), timestamp=discord.utils.utcnow())
    e.set_footer(text=f"by {ctx.author}")
    await ctx.send(embed=e)

@bot.command(name="poll")
@ba_or_perm("manage_messages")
async def poll_cmd(ctx, *, question: str):
    e = discord.Embed(title="Poll", description=question, color=discord.Color.blurple())
    e.set_footer(text=f"by {ctx.author}")
    msg = await ctx.send(embed=e)
    await msg.add_reaction("YES")
    await msg.add_reaction("NO")

@bot.command(name="choose")
async def choose_cmd(ctx, *, options: str):
    choices = [o.strip() for o in options.split("|") if o.strip()]
    if len(choices) < 2: return await ctx.send("Give at least 2 choices separated by |")
    await ctx.send(f"I choose: **{random.choice(choices)}**")

@bot.command(name="reverse")
async def reverse_cmd(ctx, *, text: str): await ctx.send(text[::-1])

@bot.command(name="clap")
async def clap_cmd(ctx, *, text: str): await ctx.send(" :clap: ".join(text.split()))

@bot.command(name="repeat")
async def repeat_cmd(ctx, times: int, *, text: str):
    times = min(times, 5)
    await ctx.send(("\n".join([text] * times)) or "Nothing to repeat.")

@bot.command(name="f")
async def f_cmd(ctx, *, thing: str = "that"): await ctx.send(f"F in the chat for **{thing}** :regional_indicator_f:")

@bot.command(name="owo")
async def owo_cmd(ctx, *, text: str):
    result = text.replace("r", "w").replace("R", "W").replace("l", "w").replace("L", "W")
    await ctx.send(f"{result} owo")

@bot.command(name="shrug")
async def shrug_cmd(ctx): await ctx.send(r"¯\_(ツ)_/¯")

@bot.command(name="lenny")
async def lenny_cmd(ctx): await ctx.send("( ͡° ͜ʖ ͡°)")

@bot.command(name="tableflip")
async def tableflip_cmd(ctx): await ctx.send("(╯°□°）╯︵ ┻━┻")

@bot.command(name="unflip")
async def unflip_cmd(ctx): await ctx.send("┬──┬ ノ( ゜-゜ノ)")

@bot.command(name="brainsize")
async def brainsize_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    size = random.randint(0, 20)
    e = discord.Embed(title=f"Brain Size -- {m.display_name}", description=f"8{'=' * size}D {size}cm", color=discord.Color.blue())
    await ctx.send(embed=e)

@bot.command(name="luck")
async def luck_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    lvl = random.randint(0, 100)
    e = discord.Embed(title=f"Luck -- {m.display_name}", description=f"**{lvl}%** luck today", color=discord.Color.gold())
    await ctx.send(embed=e)

@bot.command(name="rizz")
async def rizz_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    lvl = random.randint(0, 100)
    verdict = "No rizz. It's actually impressive." if lvl < 20 else "Low rizz." if lvl < 50 else "Mid rizz." if lvl < 75 else "W rizz. Certified smooth."
    e = discord.Embed(title=f"Rizz Check -- {m.display_name}", description=f"**{lvl}%** rizz -- {verdict}", color=discord.Color.red())
    await ctx.send(embed=e)

@bot.command(name="uwuify")
async def uwuify_cmd(ctx, *, text: str):
    result = text.replace("r", "w").replace("l", "w").replace("R", "W").replace("L", "W")
    result = result.replace("n", "ny").replace("N", "Ny")
    await ctx.send(f"{result} uwu")

@bot.command(name="spoiler")
async def spoiler_cmd(ctx, *, text: str): await ctx.send(f"||{text}||")

@bot.command(name="wordcount")
async def wordcount_cmd(ctx, *, text: str):
    words = len(text.split())
    chars = len(text)
    await ctx.send(f"**{words}** words, **{chars}** characters")

# ====================================================================
# UTILITY COMMANDS
# ====================================================================

@bot.command(name="ping")
async def ping_cmd(ctx):
    ms = round(bot.latency * 1000)
    color = discord.Color.green() if ms < 100 else discord.Color.orange() if ms < 200 else discord.Color.red()
    await ctx.send(embed=discord.Embed(title="Pong!", description=f"**{ms}ms**", color=color))

@bot.command(name="uptime")
async def uptime_cmd(ctx):
    up = int(time.time() - _uptime)
    uh, rem = divmod(up, 3600); um, us = divmod(rem, 60)
    await ctx.send(f"Uptime: **{uh}h {um}m {us}s**")

@bot.command(name="calculate", aliases=["calc", "math"])
async def calculate_cmd(ctx, *, expr: str):
    expr_clean = re.sub(r"[^0-9+\-*/()., %]", "", expr)
    if not expr_clean: return await ctx.send("Invalid expression.")
    try:
        result = eval(expr_clean, {"__builtins__": {}})
        await ctx.send(f"`{expr_clean}` = **{result}**")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command(name="base64")
async def base64_cmd(ctx, action: str, *, text: str):
    action = action.lower()
    if action in ("encode", "enc"):
        result = base64.b64encode(text.encode()).decode()
        await ctx.send(f"```{result}```")
    elif action in ("decode", "dec"):
        try:
            result = base64.b64decode(text.encode()).decode()
            await ctx.send(f"```{result}```")
        except: await ctx.send("Invalid base64 string.")
    else:
        await ctx.send("Use `,base64 encode` or `,base64 decode`.")

@bot.command(name="timestamp")
async def timestamp_cmd(ctx):
    now = int(discord.utils.utcnow().timestamp())
    e = discord.Embed(title="Current Timestamp", color=discord.Color.blurple())
    e.add_field(name="Unix",     value=f"`{now}`", inline=True)
    e.add_field(name="Short",    value=f"<t:{now}:t>",  inline=True)
    e.add_field(name="Long",     value=f"<t:{now}:F>",  inline=True)
    e.add_field(name="Relative", value=f"<t:{now}:R>",  inline=True)
    e.add_field(name="Raw",      value=f"`<t:{now}:F>`", inline=True)
    await ctx.send(embed=e)

@bot.command(name="snowflake")
async def snowflake_cmd(ctx, snowflake_id: int):
    ts = ((snowflake_id >> 22) + 1420070400000) / 1000
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    e = discord.Embed(title="Snowflake Lookup", color=discord.Color.blurple())
    e.add_field(name="ID",       value=snowflake_id, inline=True)
    e.add_field(name="Created",  value=f"<t:{int(ts)}:F>", inline=True)
    e.add_field(name="Relative", value=f"<t:{int(ts)}:R>", inline=True)
    await ctx.send(embed=e)

@bot.command(name="color")
async def color_cmd(ctx, hex_color: str):
    hex_clean = hex_color.lstrip("#")
    if len(hex_clean) != 6: return await ctx.send("Provide a valid hex color like `#FF5733`.")
    try:
        r, g, b = int(hex_clean[0:2], 16), int(hex_clean[2:4], 16), int(hex_clean[4:6], 16)
        int_color = int(hex_clean, 16)
    except: return await ctx.send("Invalid hex color.")
    e = discord.Embed(title=f"Color #{hex_clean.upper()}", color=int_color)
    e.add_field(name="Hex",   value=f"#{hex_clean.upper()}", inline=True)
    e.add_field(name="RGB",   value=f"({r}, {g}, {b})",      inline=True)
    e.add_field(name="Int",   value=int_color,               inline=True)
    e.set_image(url=f"https://singlecolorimage.com/get/{hex_clean}/200x50")
    await ctx.send(embed=e)

@bot.command(name="password", aliases=["pw"])
async def password_cmd(ctx, length: int = 16):
    import string
    length = max(8, min(length, 64))
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = "".join(random.choices(chars, k=length))
    try:
        await ctx.author.send(f"Generated password ({length} chars):\n```{pwd}```\nDelete this message after saving it!")
        await ctx.send("Password sent to your DMs.", delete_after=5)
    except:
        await ctx.send(f"```{pwd}```", delete_after=15)

@bot.command(name="define")
async def define_cmd(ctx, *, word: str):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://api.dictionaryapi.dev/api/v2/entries/en/{word.lower()}", timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200: return await ctx.send(f"No definition found for **{word}**.")
                data = await r.json()
        entry = data[0]
        meaning = entry["meanings"][0]
        defn = meaning["definitions"][0]
        e = discord.Embed(title=f"Definition: {entry['word']}", color=discord.Color.blurple())
        e.add_field(name=meaning["partOfSpeech"], value=defn["definition"], inline=False)
        if defn.get("example"): e.add_field(name="Example", value=defn["example"], inline=False)
        if entry.get("phonetic"): e.add_field(name="Phonetic", value=entry["phonetic"], inline=True)
        await ctx.send(embed=e)
    except Exception as ex:
        await ctx.send(f"Error: {ex}")

@bot.command(name="crypto")
async def crypto_cmd(ctx, coin: str = "bitcoin"):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://api.coingecko.com/api/v3/simple/price?ids={coin.lower()}&vs_currencies=usd,eur&include_24hr_change=true", timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200: return await ctx.send(f"Coin not found: **{coin}**")
                data = await r.json()
        if not data: return await ctx.send(f"Coin not found: **{coin}**")
        key = list(data.keys())[0]
        d = data[key]
        change = d.get("usd_24h_change", 0)
        color = discord.Color.green() if change >= 0 else discord.Color.red()
        e = discord.Embed(title=f"Crypto -- {key.upper()}", color=color)
        e.add_field(name="USD",       value=f"${d.get('usd', '?'):,}", inline=True)
        e.add_field(name="EUR",       value=f"€{d.get('eur', '?'):,}", inline=True)
        e.add_field(name="24h",       value=f"{change:+.2f}%",          inline=True)
        await ctx.send(embed=e)
    except Exception as ex:
        await ctx.send(f"Error: {ex}")

@bot.command(name="qr")
async def qr_cmd(ctx, *, text: str):
    url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={text.replace(' ', '+')}"
    e = discord.Embed(title="QR Code", description=text[:100], color=discord.Color.blurple())
    e.set_image(url=url)
    await ctx.send(embed=e)

@bot.command(name="weather")
async def weather_cmd(ctx, *, city: str):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://wttr.in/{city.replace(' ', '+')}?format=j1", timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200: return await ctx.send("City not found.")
                data = await r.json()
        cur = data["current_condition"][0]
        area = data["nearest_area"][0]
        city_name = area["areaName"][0]["value"]
        country   = area["country"][0]["value"]
        temp_c    = cur["temp_C"]
        temp_f    = cur["temp_F"]
        feels     = cur["FeelsLikeC"]
        humidity  = cur["humidity"]
        desc      = cur["weatherDesc"][0]["value"]
        e = discord.Embed(title=f"Weather -- {city_name}, {country}", description=desc, color=discord.Color.blue())
        e.add_field(name="Temp",     value=f"{temp_c}C / {temp_f}F", inline=True)
        e.add_field(name="Feels",    value=f"{feels}C", inline=True)
        e.add_field(name="Humidity", value=f"{humidity}%", inline=True)
        e.set_footer(text="wttr.in")
        await ctx.send(embed=e)
    except Exception as ex:
        await ctx.send(f"Weather lookup failed: {ex}")

@bot.command(name="charinfo")
async def charinfo_cmd(ctx, char: str):
    c = char[0]
    e = discord.Embed(title=f"Character Info: {c}", color=discord.Color.blurple())
    e.add_field(name="Char",    value=c, inline=True)
    e.add_field(name="Unicode", value=f"U+{ord(c):04X}", inline=True)
    e.add_field(name="Name",    value=c.encode("unicode_escape").decode(), inline=True)
    e.add_field(name="Decimal", value=ord(c), inline=True)
    await ctx.send(embed=e)

# ====================================================================
# HELP
# ====================================================================

@bot.command(name="help")
async def help_cmd(ctx, category: str = None):
    if not category:
        e = discord.Embed(
            title=f"Digit v{VER} -- Help",
            description=(
                f"Prefix: `{PREFIX}` | `{PREFIX}help <category>` for details\n\n"
                f"`{PREFIX}help protect` -- Anti-Nuke & Security\n"
                f"`{PREFIX}help mod`     -- Moderation\n"
                f"`{PREFIX}help purge`   -- Purge Commands\n"
                f"`{PREFIX}help roles`   -- Role Management\n"
                f"`{PREFIX}help server`  -- Server/Channel Cmds\n"
                f"`{PREFIX}help roblox`  -- Roblox Alerts\n"
                f"`{PREFIX}help fun`     -- Fun Commands\n"
                f"`{PREFIX}help util`    -- Utility\n"
                f"`{PREFIX}help info`    -- User/Bot Info"
            ),
            color=discord.Color.blurple()
        )
        e.add_field(name="Quick Start", value=f"Run `,setup #channel` first!", inline=False)
        e.set_footer(text=f"Digit v{VER} | {len(bot.commands)} total commands")
        return await ctx.send(embed=e)

    cat = category.lower()

    if cat in ("protect", "security", "antinuke"):
        e = discord.Embed(title="Protection Commands", color=discord.Color.green())
        cmds = [
            (",setup [#ch]",             "Enable all protection + set log channel"),
            (",antinuke on|off|status",  "Toggle anti-nuke"),
            (",antiraid on|off|status",  "Toggle anti-raid"),
            (",antispam on|off|status",  "Toggle anti-spam"),
            (",joingate on|off",         "Toggle account age gate"),
            (",setage <days>",           "Minimum account age (joingate must be on)"),
            (",whitelist @u",            "Whitelist a user from auto-actions"),
            (",unwhitelist @u",          "Remove from whitelist"),
            (",whitelisted",             "List whitelisted users"),
            (",lockdown",                "Lock all channels immediately"),
            (",unlock",                  "Lift lockdown"),
            (",channellock [#ch]",       "Lock a specific channel"),
            (",channelunlock [#ch]",     "Unlock a specific channel"),
            (",quarantine @u",           "Remove all roles from a user"),
            (",unquarantine @u",         "Restore their roles"),
            (",setautoban {id}",         "Auto-ban a user when they join"),
            (",setunautoban {id}",       "Remove from auto-ban list"),
            (",listautoban",             "Show auto-ban list"),
            (",botaccess @u",            "Grant full bot access"),
            (",revokebotaccess @u",      "Revoke bot access"),
            (",listbotaccess",           "List bot admins"),
            (",status",                  "Full security dashboard"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat in ("mod", "moderation"):
        e = discord.Embed(title="Moderation Commands", color=discord.Color.red())
        cmds = [
            (",ban @u [reason]",         "Permanent ban"),
            (",unban <id>",              "Unban by ID"),
            (",kick @u [reason]",        "Kick"),
            (",softban @u [reason]",     "Ban + unban (clears messages)"),
            (",tempban @u <dur> [r]",    "Temp ban (10m, 2h, 1d)"),
            (",mute @u <dur> [reason]",  "Timeout (10m, 2h, 1d)"),
            (",unmute @u",               "Remove timeout"),
            (",warn @u [reason]",        "Warn a user"),
            (",warnings @u",             "View warnings"),
            (",clearwarns @u",           "Clear all warnings"),
            (",delwarn @u <#>",          "Delete a specific warning"),
            (",note @u <text>",          "Add a staff note"),
            (",notes @u",               "View notes"),
            (",clearnotes @u",           "Clear notes"),
            (",modlogs @u",              "View mod history"),
            (",clearmodlogs @u",         "Clear mod history"),
            (",nick @u [name]",          "Change nickname"),
            (",resetnick @u",            "Reset nickname"),
            (",deafen @u",               "Server deafen"),
            (",undeafen @u",             "Remove deafen"),
            (",voicekick @u",            "Disconnect from voice"),
            (",voicemove @u #ch",        "Move to voice channel"),
            (",massban <ids...>",        "Ban multiple users by ID"),
            (",announce [#ch] <text>",   "Send announcement embed"),
            (",dm @u <message>",         "DM a user as staff"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat == "purge":
        e = discord.Embed(title="Purge Commands", color=discord.Color.orange())
        cmds = [
            (",purge <amount>",          "Delete messages (no cap, any amount)"),
            (",purgeuser @u [amount]",   "Delete messages from specific user"),
            (",purgebotz [amount]",      "Delete bot messages"),
            (",purgeuntil <msg_id>",     "Delete all messages after message ID"),
            (",slowmode [sec]",          "Set slowmode (0 = off)"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat in ("roles", "role"):
        e = discord.Embed(title="Role Commands", color=discord.Color.blurple())
        cmds = [
            (",role add @u @role",       "Add role to user"),
            (",role remove @u @role",    "Remove role from user"),
            (",roleall @role",           "Give role to all members"),
            (",rolerall @role",          "Remove role from all members"),
            (",createrole <name> [hex]", "Create a role"),
            (",deleterole @role",        "Delete a role"),
            (",rolecolor @role <hex>",   "Change role color"),
            (",rolehoist @role",         "Toggle role hoist"),
            (",rolemention @role",       "Toggle role mentionable"),
            (",roleinfo @role",          "Role information"),
            (",rolelist",                "List all roles"),
            (",inrole @role",            "Members with role"),
            (",roleperms @role",         "Role permissions"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat in ("server", "channel"):
        e = discord.Embed(title="Server/Channel Commands", color=discord.Color.blurple())
        cmds = [
            (",createchannel <name> [type]",  "Create channel (text/voice/category)"),
            (",deletechannel [#ch]",           "Delete a channel"),
            (",channelinfo [#ch]",             "Channel information"),
            (",channeltopic [#ch] <topic>",    "Set channel topic"),
            (",channelname #ch <name>",        "Rename a channel"),
            (",clonechannel [#ch]",            "Clone a channel"),
            (",nsfw [#ch]",                    "Toggle NSFW"),
            (",sendmsg #ch <text>",            "Send message as bot"),
            (",addmoji <name> <url>",          "Add emoji from URL"),
            (",steal <emoji> [name]",          "Steal emoji from another server"),
            (",setverification <level>",       "Set verification level"),
            (",invites",                       "List active invites"),
            (",emojis",                        "List server emojis"),
            (",boosts",                        "Show boosters"),
            (",servericon",                    "Show server icon"),
            (",serverinfo",                    "Server statistics"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat == "roblox":
        e = discord.Embed(
            title="Roblox Commands",
            description="Digit watches for Roblox updates every 5 minutes across all platforms.",
            color=0xFF0000
        )
        cmds = [
            (",robloxversion",               "Current versions for all platforms"),
            (",robloxstatus",                "Roblox server status"),
            (",robloxinfo <username>",       "Roblox user profile lookup"),
            (",setrobloxchannel [#ch]",      "Set channel for update alerts"),
            (",robloxupdates on|off|status", "Toggle update alerts for this server"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)
        e.add_field(name="Platforms Monitored", value="Windows | Mac | Android | iOS | Studio", inline=False)

    elif cat == "fun":
        e = discord.Embed(title="Fun Commands", color=discord.Color.gold())
        cmds = [
            (",ratio [@u]",      "Ratio someone"), (",iq [@u]", "IQ test"), (",roast [@u]", "Roast"),
            (",sus [@u]",        "Sus check"),   (",touchgrass [@u]", "Go outside"),
            (",skill [@u]",      "Skill rating"), (",ship @u [@u]", "Ship check"),
            (",hack [@u]",       "Totally real hacking"), (",coinflip", "Heads/tails"),
            (",dice [sides]",    "Roll dice"),    (",rate <thing>", "Rate anything"),
            (",rps <choice>",    "Rock paper scissors"), (",8ball <q>", "Magic 8-ball"),
            (",mock <text>",     "mOcK tExT"),   (",say <text>", "Bot says it"),
            (",poll <question>", "Create a poll"), (",choose a|b|c", "Pick random option"),
            (",reverse <text>",  "Reverse text"), (",clap <text>", "Clap text"),
            (",repeat <n> <t>",  "Repeat text"),  (",f <thing>", "Pay respects"),
            (",owo <text>",      "OwO"),          (",shrug", r"¯\_(ツ)_/¯"),
            (",lenny",           "Lenny face"),   (",tableflip", "Table flip"),
            (",brainsize [@u]",  "Brain check"),  (",luck [@u]", "Luck check"),
            (",rizz [@u]",       "Rizz check"),   (",uwuify <text>", "UwU"),
            (",spoiler <text>",  "||Spoiler||"),  (",wordcount <text>", "Count words"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=True)

    elif cat in ("util", "utility"):
        e = discord.Embed(title="Utility Commands", color=discord.Color.blurple())
        cmds = [
            (",ping",                    "Bot latency"),
            (",uptime",                  "Bot uptime"),
            (",calculate <expr>",        "Math calculator"),
            (",base64 encode|decode <t>","Base64 encode/decode"),
            (",timestamp",               "Current timestamp"),
            (",snowflake <id>",          "Discord snowflake lookup"),
            (",color <hex>",             "Color info"),
            (",password [length]",       "Generate secure password"),
            (",define <word>",           "Dictionary definition"),
            (",crypto <coin>",           "Crypto price"),
            (",qr <text>",               "Generate QR code"),
            (",weather <city>",          "Current weather"),
            (",charinfo <char>",         "Unicode character info"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    elif cat in ("info", "user"):
        e = discord.Embed(title="Info Commands", color=discord.Color.blurple())
        cmds = [
            (",userinfo [@u]",   "User info (alias: whois)"),
            (",avatar [@u]",     "Get avatar (alias: av)"),
            (",banner [@u]",     "Get profile banner"),
            (",perms [@u]",      "User permissions"),
            (",joined [@u]",     "Join/create dates"),
            (",botinfo",         "Bot info"),
            (",serverinfo",      "Server stats"),
            (",membercount",     "Member count breakdown"),
            (",rolelist",        "All server roles"),
        ]
        for cmd, desc in cmds: e.add_field(name=f"`{cmd}`", value=desc, inline=False)

    else:
        return await ctx.send(f"Unknown category. Run `,help` for the full menu.", delete_after=5)

    e.set_footer(text=f"Digit v{VER} | prefix: {PREFIX}")
    await ctx.send(embed=e)

# ====================================================================
# ENTRY POINT
# ====================================================================

if __name__ == "__main__":
    TOKEN = os.getenv("DISCORD_TOKEN", "")
    if not TOKEN:
        print("ERROR: Set DISCORD_TOKEN environment variable first.")
        print("  Windows: set DISCORD_TOKEN=your_token_here")
        print("  Linux:   export DISCORD_TOKEN=your_token_here")
    else:
        print(f"Starting Digit v{VER}...")
        bot.run(TOKEN)
