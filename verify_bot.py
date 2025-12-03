import discord
from discord.ext import commands, tasks
from discord import app_commands
import logging
from dotenv import load_dotenv 
from datetime import datetime, timedelta, timezone
import os
import smtplib
import random

load_dotenv()
token = os.getenv("DISCORD_TOKEN")
sender_passcode = os.getenv("sender_passcode")
handler = logging.FileHandler(filename="discord.log", encoding ="utf-8", mode="w")
intents = discord.Intents.all()

intents = discord.Intents.all()

bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)

ROLE_NAME = "Verified"
SENDER_EMAIL = ""
CODE_EXP = timedelta(minutes=10)

# Rate limit: allow up to 3 /verify calls per 10 minutes, then block for 10 minutes
VERIFY_WINDOW = timedelta(minutes=10)
VERIFY_BLOCK = timedelta(minutes=10)

# user_id -> {"netid": str, "code": str, "expires_at": datetime(UTC)}
pending_verification: dict[int, dict] = {}

# user_id -> {"hits": int, "window_start": datetime(UTC), "blocked_until": datetime(UTC) | None}
verify_ratelimit: dict[int, dict] = {}

def send_verification_email(netid: str, code: str):
    recipient = f"{netid}@illinois.edu"
    subject = "Discord Verification Code"
    body = (
        f"Here is your verification code for GTO Illini: {code}\n\n"
        "If you did not initiate this verification process, please disregard this email."
    )
    message = f"From: {SENDER_EMAIL}\r\nTo: {recipient}\r\nSubject: {subject}\r\n\r\n{body}"
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, sender_passcode)
        server.sendmail(SENDER_EMAIL, [recipient], message)

# -----Helper functions-----
def time_now() -> datetime:
    return datetime.now(timezone.utc)

def is_expired(rec: dict) -> bool:
    return time_now() > rec["expires_at"]

async def get_member_or_none(inter: discord.Interaction) -> discord.Member | None:
    if inter.guild is None:
        return None
    member = inter.guild.get_member(inter.user.id)
    if member is None:
        try:
            member = await inter.guild.fetch_member(inter.user.id)
        except discord.NotFound:
            return None
    return member

def member_has_verified(member: discord.Member) -> bool:
    return any(r.name == ROLE_NAME for r in member.roles)

def cooldown_remaining(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    m, s = divmod(max(total, 0), 60)
    if m and s:
        return f"{m}minutes and {s}seconds"
    if m:
        return f"{m}minutes"
    return f"{s}seconds"

def check_and_update_verify_ratelimit(user_id: int) -> tuple[bool, str | None]:
    """
    Returns (allowed, reason).
    - If not allowed, reason is a human message describing remaining block.
    - If allowed, updates the ratelimit counters.
    """
    now = time_now()
    rec = verify_ratelimit.get(user_id)

    if rec and rec.get("blocked_until"):
        if now < rec["blocked_until"]:
            remaining = rec["blocked_until"] - now
            return False, f"You're rate-limited for **{cooldown_remaining(remaining)}** due to too many `/verify` attempts."
        else:
            # Block expired; reset
            verify_ratelimit[user_id] = {
                "hits": 1,
                "window_start": now,
                "blocked_until": None
            }
            return True, None

    if not rec:
        verify_ratelimit[user_id] = {
            "hits": 1,
            "window_start": now,
            "blocked_until": None
        }
        return True, None

    # Existing record
    window_start = rec["window_start"]
    if now - window_start > VERIFY_WINDOW:
        # New window
        verify_ratelimit[user_id] = {
            "hits": 1,
            "window_start": now,
            "blocked_until": None
        }
        return True, None

    # Same window
    rec["hits"] += 1
    if rec["hits"] > 3:
        rec["blocked_until"] = now + VERIFY_BLOCK
        remaining = rec["blocked_until"] - now
        return False, f"Too many `/verify` attempts. Try again in **{cooldown_remaining(remaining)}**."
    return True, None

# -----Commands-----
@bot.tree.command(name="verify", description="Send a verification code to your illinois.edu email.")
@app_commands.describe(netid="Your Illinois NetID (e.g., jdoe3)")
async def verify(inter: discord.Interaction, netid: str):
    member = await get_member_or_none(inter)
    if member is None:
        await inter.response.send_message(
            "Please run this command inside the server (not in DMs).",
            ephemeral=True
        )
        return

    # Already verified?
    if member_has_verified(member):
        verify_ratelimit.pop(inter.user.id, None)
        await inter.response.send_message(
            "You have already been verified!",
            ephemeral=True
        )
        return

    # Rate-limit check/update
    allowed, reason = check_and_update_verify_ratelimit(inter.user.id)
    if not allowed:
        await inter.response.send_message(reason, ephemeral=True)
        return

    # Generate/overwrite code (10-min TTL)
    code = f"{random.randint(100000, 999999)}"
    pending_verification[inter.user.id] = {
        "netid": netid,
        "code": code,
        "expires_at": time_now() + CODE_EXP
    }

    try:
        send_verification_email(netid, code)
        await inter.response.send_message(
            f"A verification code has been sent to **{netid}@illinois.edu**. "
            f"It expires in **10 minutes**.\n"
            "If you don't see it, check your spam/junk folder.\n\n"
            "When ready, run `/code 123456` (replace 123456 with your code).",
            ephemeral=True
        )
    except Exception as e:
        print("Email error:", e)
        await inter.response.send_message(
            "Sorry—there was an error sending your email. Please try again or contact an admin.",
            ephemeral=True
        )

@bot.tree.command(name="code", description="Submit the 6-digit verification code from your email.")
@app_commands.describe(entered_code="Your 6-digit verification code")
async def code_command(inter: discord.Interaction, entered_code: str):
    member = await get_member_or_none(inter)
    if member is None:
        await inter.response.send_message(
            "Please run this command inside the server (not in DMs).",
            ephemeral=True
        )
        return

    if member_has_verified(member):
        await inter.response.send_message(
            "You have already been verified!",
            ephemeral=True
        )
        return

    rec = pending_verification.get(inter.user.id)
    if rec is None:
        await inter.response.send_message(
            "No pending verification. Use `/verify {netid}` first.",
            ephemeral=True
        )
        return


    if entered_code != rec["code"]:
        await inter.response.send_message("Invalid code. Please try again.", ephemeral=True)
        return

    role = discord.utils.get(member.guild.roles, name=ROLE_NAME)
    if role:
        try:
            await member.add_roles(role, reason="Email verified")
        except discord.Forbidden:
            await inter.response.send_message(
                "Verified, but I don't have permission to add the role. Please contact an admin.",
                ephemeral=True
            )
            pending_verification.pop(inter.user.id, None)
            return

    try:
        await member.edit(nick=f"{member.name}({rec['netid']})")
    except discord.Forbidden:
        await inter.response.send_message(
            "You are verified! (I couldn't change your nickname due to permissions.)",
            ephemeral=True
        )
    else:
        await inter.response.send_message(
            "You are verified! Your nickname has been updated.",
            ephemeral=True
        )

    pending_verification.pop(inter.user.id, None)

@tasks.loop(minutes=10)
async def cleanup_ratelimit():
    """Runs every 10 minutes and deletes expired records."""
    now = time_now()
    removed = 0

    for uid, rec in list(verify_ratelimit.items()):
        if rec.get("blocked_until", 0) <= now or now - rec.get("window_start", 0) > VERIFY_WINDOW:
            verify_ratelimit.pop(uid, None)
            removed += 1
    for uid, rec in list(pending_verification.items()):
        if rec.get("expires_at", 0) <= now:
            pending_verification.pop(uid, None)
            removed += 1
    if removed:
        logging.debug(f"[cleanup_ratelimit] Removed {removed} expired records")

@cleanup_ratelimit.before_loop
async def before_cleanup():
    await bot.wait_until_ready()

# ----Clean-----
@bot.event
async def on_ready():
    if not cleanup_ratelimit.is_running():
        cleanup_ratelimit.start()
    await bot.tree.sync()
    print("bot is online")

# -----Start-----
bot.run(token, log_handler=handler, log_level=logging.DEBUG)
