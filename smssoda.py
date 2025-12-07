

#!/usr/bin/env python3
"""
Termux-ready OTP forwarder.
Fixed version: lxml removed → html.parser used everywhere.
"""

import time
import logging
import re
from datetime import datetime

import requests
from bs4 import BeautifulSoup
import phonenumbers

try:
    from telegram import Bot, ParseMode
except:
    raise SystemExit("Install: pip install python-telegram-bot==13.15")

# -------------------------
# CONFIG
# -------------------------
BOT_TOKEN = "8013216408:AAEzn1aISOgTAeqAPjJpeSV90B-WoY60bC0"
CHAT_ID   = -1003009238534

USERNAME  = "pcclone0"
PASSWORD  = "pcclone0"

LOGIN_URL = "http://185.2.83.39/ints/login"
FETCH_URL = "http://185.2.83.39/ints/client/SMSCDRStats"

POLL_INTERVAL   = 10
REQUEST_TIMEOUT = 15

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("otp_termux")

bot = Bot(token=BOT_TOKEN)

# -------------------------
# Utils
# -------------------------
def get_country_info(number_raw: str) -> str:
    try:
        parsed = phonenumbers.parse(number_raw, None)
        region = phonenumbers.region_code_for_number(parsed)
        flag = "".join(chr(127397 + ord(c)) for c in region.upper())
        country_name = phonenumbers.geocoder.description_for_number(parsed, "en") or region
        return f"{flag} {country_name} ({region})"
    except:
        return "Unknown"


def extract_csrf_from_html(html: str):
    soup = BeautifulSoup(html, "html.parser")
    names = ["csrfmiddlewaretoken", "csrf_token", "_token", "csrf"]
    for n in names:
        el = soup.find("input", {"name": n})
        if el and el.get("value"):
            return (n, el.get("value"))

    for m in soup.find_all("meta"):
        if m.get("name") and "csrf" in m.get("name").lower():
            return (m.get("name"), m.get("content"))

    for s in soup.find_all("script"):
        txt = s.string or ""
        m = re.search(r'(csrf[_-]?token|_csrf)\s*[:=]\s*[\'"]([^\'"]+)[\'"]', txt, re.I)
        if m:
            return ("js-csrf", m.group(2))

    return (None, None)


# -------------------------
# Login and Fetch
# -------------------------
def login_and_fetch():
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0", "Referer": LOGIN_URL}

    try:
        # GET login page
        try:
            r = session.get(LOGIN_URL, headers=headers, timeout=REQUEST_TIMEOUT)
            name, token = extract_csrf_from_html(r.text)
            logger.info(f"Login page fetched. CSRF={token}")
        except:
            name, token = (None, None)

        # possible login payloads
        form_variants = [
            {"username": USERNAME, "password": PASSWORD},
            {"email": USERNAME, "password": PASSWORD},
            {"login": USERNAME, "password": PASSWORD},
        ]

        if name and token:
            for fv in list(form_variants):
                newfv = fv.copy()
                newfv[name] = token
                form_variants.append(newfv)

        logged = False
        for data in form_variants:
            resp = session.post(LOGIN_URL, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
            logger.info(f"Tried login → {resp.status_code} using {list(data.keys())}")

            text = resp.text.lower()
            if resp.history or "logout" in text or "dashboard" in text or resp.status_code in (200,302):
                logged = True
                logger.info("Login heuristic says SUCCESS")
                break

        # Fetch data
        fr = session.get(FETCH_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        logger.info(f"Fetched messages page: {fr.status_code}")

        if fr.status_code == 200:
            return fr.text
        return None

    except Exception as e:
        logger.error(f"login_and_fetch error: {e}")
        return None


# -------------------------
# HTML Parsing
# -------------------------
def parse_messages(html: str):
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    results = []

    rows = soup.select("table tr")
    for r in rows:
        try:
            number = r.find("td", {"class":"number"}) or r.find("td", text=re.compile(r"\+?\d"))
            body   = r.find("td", {"class":"body"})   or r

            num_text = number.get_text(strip=True) if number else ""
            msg_text = body.get_text(" ", strip=True)

            otp_match = re.search(r"\b([0-9]{3,8})\b", msg_text)
            if otp_match:
                results.append({
                    "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "number": num_text,
                    "service": "Unknown",
                    "otp": otp_match.group(1),
                    "msg": msg_text,
                })
        except:
            continue

    return results


# -------------------------
# Telegram Sender
# -------------------------
def format_message(msg: dict) -> str:
    country = get_country_info(msg["number"])
    return (
        f"🔐 <b>OTP RECEIVED</b>\n\n"
        f"🕒 <b>Time:</b> {msg['time']}\n"
        f"📱 <b>Number:</b> {msg['number']}\n"
        f"🌍 <b>Country:</b> {country}\n"
        f"🔑 <b>OTP:</b> {msg['otp']}\n"
        f"💬 {msg['msg']}"
    )

def send_to_telegram(html):
    try:
        bot.send_message(chat_id=CHAT_ID, text=html, parse_mode=ParseMode.HTML)
        logger.info("OTP forwarded to Telegram")
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")


# -------------------------
# MAIN LOOP
# -------------------------
def main():
    logger.info("Forwarder started...")
    sent = set()

    while True:
        try:
            html = login_and_fetch()
            msgs = parse_messages(html)
            logger.info(f"Parsed {len(msgs)} messages")

            for m in msgs:
                key = f"{m['number']}__{m['otp']}"
                if key in sent:
                    continue
                send_to_telegram(format_message(m))
                sent.add(key)

            if len(sent) > 1000:
                sent = set(list(sent)[-500:])
        except Exception as e:
            logger.error(f"Main loop error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
