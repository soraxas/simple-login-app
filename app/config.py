import os
import random
import socket
import string
import subprocess
from ast import literal_eval
from typing import Callable
from urllib.parse import urlparse

from dotenv import load_dotenv

SHA1 = subprocess.getoutput("git rev-parse HEAD")
ROOT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def get_abs_path(file_path: str):
    """append ROOT_DIR for relative path"""
    # Already absolute path
    if file_path.startswith("/"):
        return file_path
    else:
        return os.path.join(ROOT_DIR, file_path)


def sl_getenv(env_var: str, default_factory: Callable = None):
    """
    Get env value, convert into Python object
    Args:
        env_var (str): env var, example: SL_DB
        default_factory: returns value if this env var is not set.

    """
    value = os.getenv(env_var)
    if value is None:
        return default_factory()

    return literal_eval(value)


config_file = os.environ.get("CONFIG")
if config_file:
    config_file = get_abs_path(config_file)
    print("load config file", config_file)
    load_dotenv(get_abs_path(config_file))
else:
    load_dotenv()

COLOR_LOG = "COLOR_LOG" in os.environ

# Allow user to have 1 year of premium: set the expiration_date to 1 year more
PROMO_CODE = "SIMPLEISBETTER"

# Server url
URL = os.environ["URL"]
print(">>> URL:", URL)

# Calculate RP_ID for WebAuthn
RP_ID = urlparse(URL).hostname

SENTRY_DSN = os.environ.get("SENTRY_DSN")

# can use another sentry project for the front-end to avoid noises
SENTRY_FRONT_END_DSN = os.environ.get("SENTRY_FRONT_END_DSN") or SENTRY_DSN

# Email related settings
NOT_SEND_EMAIL = "NOT_SEND_EMAIL" in os.environ
EMAIL_DOMAIN = os.environ["EMAIL_DOMAIN"].lower()
SUPPORT_EMAIL = os.environ["SUPPORT_EMAIL"]
SUPPORT_NAME = os.environ.get("SUPPORT_NAME", "Son from SimpleLogin")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")

# VERP: mail_from set to BOUNCE_PREFIX + email_log.id + BOUNCE_SUFFIX
BOUNCE_PREFIX = os.environ.get("BOUNCE_PREFIX") or "bounce+"
BOUNCE_SUFFIX = os.environ.get("BOUNCE_SUFFIX") or f"+@{EMAIL_DOMAIN}"
BOUNCE_EMAIL = BOUNCE_PREFIX + "{}" + BOUNCE_SUFFIX

# Used for VERP during reply phase. It's similar to BOUNCE_PREFIX.
# It's needed when sending emails from custom domain to respect DMARC.
# BOUNCE_PREFIX_FOR_REPLY_PHASE should never be used in any existing alias
# and can't be used for creating a new alias on custom domain
# Note BOUNCE_PREFIX_FOR_REPLY_PHASE doesn't have the trailing plus sign (+) as BOUNCE_PREFIX
BOUNCE_PREFIX_FOR_REPLY_PHASE = (
    os.environ.get("BOUNCE_PREFIX_FOR_REPLY_PHASE") or "bounce_reply"
)


# VERP for transactional email: mail_from set to BOUNCE_PREFIX + email_log.id + BOUNCE_SUFFIX
TRANSACTIONAL_BOUNCE_PREFIX = (
    os.environ.get("TRANSACTIONAL_BOUNCE_PREFIX") or "transactional+"
)
TRANSACTIONAL_BOUNCE_SUFFIX = (
    os.environ.get("TRANSACTIONAL_BOUNCE_SUFFIX") or f"+@{EMAIL_DOMAIN}"
)
TRANSACTIONAL_BOUNCE_EMAIL = (
    TRANSACTIONAL_BOUNCE_PREFIX + "{}" + TRANSACTIONAL_BOUNCE_SUFFIX
)

try:
    MAX_NB_EMAIL_FREE_PLAN = int(os.environ["MAX_NB_EMAIL_FREE_PLAN"])
except Exception:
    print("MAX_NB_EMAIL_FREE_PLAN is not set, use 5 as default value")
    MAX_NB_EMAIL_FREE_PLAN = 5

# maximum number of directory a premium user can create
MAX_NB_DIRECTORY = 50

ENFORCE_SPF = "ENFORCE_SPF" in os.environ

# allow to override postfix server locally
POSTFIX_SERVER = os.environ.get("POSTFIX_SERVER", "postfix")

DISABLE_REGISTRATION = "DISABLE_REGISTRATION" in os.environ

# allow using a different postfix port, useful when developing locally
POSTFIX_PORT = 25
if "POSTFIX_PORT" in os.environ:
    POSTFIX_PORT = int(os.environ["POSTFIX_PORT"])

# postfix port to use during the forward phase
POSTFIX_PORT_FORWARD = POSTFIX_PORT
if "POSTFIX_PORT_FORWARD" in os.environ:
    POSTFIX_PORT_FORWARD = int(os.environ["POSTFIX_PORT_FORWARD"])

# Use port 587 instead of 25 when sending emails through Postfix
# Useful when calling Postfix from an external network
POSTFIX_SUBMISSION_TLS = "POSTFIX_SUBMISSION_TLS" in os.environ

# ["domain1.com", "domain2.com"]
OTHER_ALIAS_DOMAINS = sl_getenv("OTHER_ALIAS_DOMAINS", list)
OTHER_ALIAS_DOMAINS = [d.lower().strip() for d in OTHER_ALIAS_DOMAINS]

# List of domains user can use to create alias
if "ALIAS_DOMAINS" in os.environ:
    ALIAS_DOMAINS = sl_getenv("ALIAS_DOMAINS")  # ["domain1.com", "domain2.com"]
else:
    ALIAS_DOMAINS = OTHER_ALIAS_DOMAINS + [EMAIL_DOMAIN]
ALIAS_DOMAINS = [d.lower().strip() for d in ALIAS_DOMAINS]

# ["domain1.com", "domain2.com"]
PREMIUM_ALIAS_DOMAINS = sl_getenv("PREMIUM_ALIAS_DOMAINS", list)
PREMIUM_ALIAS_DOMAINS = [d.lower().strip() for d in PREMIUM_ALIAS_DOMAINS]

# the alias domain used when creating the first alias for user
FIRST_ALIAS_DOMAIN = os.environ.get("FIRST_ALIAS_DOMAIN") or EMAIL_DOMAIN

# list of (priority, email server)
# e.g. [(10, "mx1.hostname."), (10, "mx2.hostname.")]
EMAIL_SERVERS_WITH_PRIORITY = sl_getenv("EMAIL_SERVERS_WITH_PRIORITY")

# these emails are ignored when computing stats
IGNORED_EMAILS = sl_getenv("IGNORED_EMAILS", list)

# disable the alias suffix, i.e. the ".random_word" part
DISABLE_ALIAS_SUFFIX = "DISABLE_ALIAS_SUFFIX" in os.environ

# the email address that receives all unsubscription request
UNSUBSCRIBER = os.environ.get("UNSUBSCRIBER")

DKIM_SELECTOR = b"dkim"
DKIM_HEADERS = [b"from", b"to"]
DKIM_PRIVATE_KEY = None

if "DKIM_PRIVATE_KEY_PATH" in os.environ:
    DKIM_PRIVATE_KEY_PATH = get_abs_path(os.environ["DKIM_PRIVATE_KEY_PATH"])
    with open(DKIM_PRIVATE_KEY_PATH) as f:
        DKIM_PRIVATE_KEY = f.read()


# Database
DB_URI = os.environ["DB_URI"]

# Flask secret
FLASK_SECRET = os.environ["FLASK_SECRET"]
SESSION_COOKIE_NAME = "slapp"
MAILBOX_SECRET = FLASK_SECRET + "mailbox"
CUSTOM_ALIAS_SECRET = FLASK_SECRET + "custom_alias"

# AWS
AWS_REGION = os.environ.get("AWS_REGION") or "eu-west-3"
BUCKET = os.environ.get("BUCKET")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

# Paddle
try:
    PADDLE_VENDOR_ID = int(os.environ["PADDLE_VENDOR_ID"])
    PADDLE_MONTHLY_PRODUCT_ID = int(os.environ["PADDLE_MONTHLY_PRODUCT_ID"])
    PADDLE_YEARLY_PRODUCT_ID = int(os.environ["PADDLE_YEARLY_PRODUCT_ID"])
except (KeyError, ValueError):
    print("Paddle param not set")
    PADDLE_VENDOR_ID = -1
    PADDLE_MONTHLY_PRODUCT_ID = -1
    PADDLE_YEARLY_PRODUCT_ID = -1

# Other Paddle product IDS
PADDLE_MONTHLY_PRODUCT_IDS = sl_getenv("PADDLE_MONTHLY_PRODUCT_IDS", list)
PADDLE_MONTHLY_PRODUCT_IDS.append(PADDLE_MONTHLY_PRODUCT_ID)

PADDLE_YEARLY_PRODUCT_IDS = sl_getenv("PADDLE_YEARLY_PRODUCT_IDS", list)
PADDLE_YEARLY_PRODUCT_IDS.append(PADDLE_YEARLY_PRODUCT_ID)

PADDLE_PUBLIC_KEY_PATH = get_abs_path(
    os.environ.get("PADDLE_PUBLIC_KEY_PATH", "local_data/paddle.key.pub")
)

PADDLE_AUTH_CODE = os.environ.get("PADDLE_AUTH_CODE")

# OpenID keys, used to sign id_token
OPENID_PRIVATE_KEY_PATH = get_abs_path(
    os.environ.get("OPENID_PRIVATE_KEY_PATH", "local_data/jwtRS256.key")
)
OPENID_PUBLIC_KEY_PATH = get_abs_path(
    os.environ.get("OPENID_PUBLIC_KEY_PATH", "local_data/jwtRS256.key.pub")
)

# Used to generate random email
WORDS_FILE_PATH = get_abs_path(
    os.environ.get("WORDS_FILE_PATH", "local_data/words_alpha.txt")
)

# Used to generate random email
if os.environ.get("GNUPGHOME"):
    GNUPGHOME = get_abs_path(os.environ.get("GNUPGHOME"))
else:
    letters = string.ascii_lowercase
    random_dir_name = "".join(random.choice(letters) for _ in range(20))
    GNUPGHOME = f"/tmp/{random_dir_name}"
    if not os.path.exists(GNUPGHOME):
        os.mkdir(GNUPGHOME, mode=0o700)

    print("WARNING: Use a temp directory for GNUPGHOME", GNUPGHOME)

# Github, Google, Facebook client id and secrets
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

FACEBOOK_CLIENT_ID = os.environ.get("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.environ.get("FACEBOOK_CLIENT_SECRET")

# in seconds
AVATAR_URL_EXPIRATION = 3600 * 24 * 7  # 1h*24h/d*7d=1week

# session key
MFA_USER_ID = "mfa_user_id"

FLASK_PROFILER_PATH = os.environ.get("FLASK_PROFILER_PATH")
FLASK_PROFILER_PASSWORD = os.environ.get("FLASK_PROFILER_PASSWORD")

# Job names
JOB_ONBOARDING_1 = "onboarding-1"
JOB_ONBOARDING_2 = "onboarding-2"
JOB_ONBOARDING_3 = "onboarding-3"
JOB_ONBOARDING_4 = "onboarding-4"
JOB_BATCH_IMPORT = "batch-import"
JOB_DELETE_ACCOUNT = "delete-account"

# for pagination
PAGE_LIMIT = 20

# Upload to static/upload instead of s3
LOCAL_FILE_UPLOAD = "LOCAL_FILE_UPLOAD" in os.environ
UPLOAD_DIR = None

# Rate Limiting
# nb max of activity (forward/reply) an alias can have during 1 min
MAX_ACTIVITY_DURING_MINUTE_PER_ALIAS = 10

# nb max of activity (forward/reply) a mailbox can have during 1 min
MAX_ACTIVITY_DURING_MINUTE_PER_MAILBOX = 15

if LOCAL_FILE_UPLOAD:
    print("Upload files to local dir")
    UPLOAD_DIR = os.path.join(ROOT_DIR, "static/upload")
    if not os.path.exists(UPLOAD_DIR):
        print("Create upload dir")
        os.makedirs(UPLOAD_DIR)

LANDING_PAGE_URL = os.environ.get("LANDING_PAGE_URL") or "https://simplelogin.io"

STATUS_PAGE_URL = os.environ.get("STATUS_PAGE_URL") or "https://status.simplelogin.io"

# Loading PGP keys when mail_handler runs. To be used locally when init_app is not called.
LOAD_PGP_EMAIL_HANDLER = "LOAD_PGP_EMAIL_HANDLER" in os.environ

DISPOSABLE_FILE_PATH = get_abs_path(
    os.environ.get("DISPOSABLE_FILE_PATH", "local_data/local_disposable_domains.txt")
)

with open(get_abs_path(DISPOSABLE_FILE_PATH), "r") as f:
    DISPOSABLE_EMAIL_DOMAINS = f.readlines()
    DISPOSABLE_EMAIL_DOMAINS = [d.strip().lower() for d in DISPOSABLE_EMAIL_DOMAINS]
    DISPOSABLE_EMAIL_DOMAINS = [
        d for d in DISPOSABLE_EMAIL_DOMAINS if not d.startswith("#")
    ]

# Used when querying info on Apple API
# for iOS App
APPLE_API_SECRET = os.environ.get("APPLE_API_SECRET")
# for Mac App
MACAPP_APPLE_API_SECRET = os.environ.get("MACAPP_APPLE_API_SECRET")

# <<<<< ALERT EMAIL >>>>

# maximal number of alerts that can be sent to the same email in 24h
MAX_ALERT_24H = 4

# When a reverse-alias receives emails from un unknown mailbox
ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX = "reverse_alias_unknown_mailbox"

# When a forwarding email is bounced
ALERT_BOUNCE_EMAIL = "bounce"

ALERT_BOUNCE_EMAIL_REPLY_PHASE = "bounce-when-reply"

# When a forwarding email is detected as spam
ALERT_SPAM_EMAIL = "spam"

# When an email is sent from a mailbox to an alias - a cycle
ALERT_SEND_EMAIL_CYCLE = "cycle"

ALERT_SPF = "spf"

# when a mailbox is also an alias
# happens when user adds a mailbox with their domain
# then later adds this domain into SimpleLogin
ALERT_MAILBOX_IS_ALIAS = "mailbox_is_alias"

AlERT_WRONG_MX_RECORD_CUSTOM_DOMAIN = "custom_domain_mx_record_issue"

# alert when a new alias is about to be created on a disabled directory
ALERT_DIRECTORY_DISABLED_ALIAS_CREATION = "alert_directory_disabled_alias_creation"

# <<<<< END ALERT EMAIL >>>>

# Disable onboarding emails
DISABLE_ONBOARDING = "DISABLE_ONBOARDING" in os.environ

HCAPTCHA_SECRET = os.environ.get("HCAPTCHA_SECRET")
HCAPTCHA_SITEKEY = os.environ.get("HCAPTCHA_SITEKEY")

PLAUSIBLE_HOST = os.environ.get("PLAUSIBLE_HOST")
PLAUSIBLE_DOMAIN = os.environ.get("PLAUSIBLE_DOMAIN")

# server host
HOST = socket.gethostname()

SPAMASSASSIN_HOST = os.environ.get("SPAMASSASSIN_HOST")
# by default use a tolerant score
if "MAX_SPAM_SCORE" in os.environ:
    MAX_SPAM_SCORE = float(os.environ["MAX_SPAM_SCORE"])
else:
    MAX_SPAM_SCORE = 5.5

# use a more restrictive score when replying
if "MAX_REPLY_PHASE_SPAM_SCORE" in os.environ:
    MAX_REPLY_PHASE_SPAM_SCORE = float(os.environ["MAX_REPLY_PHASE_SPAM_SCORE"])
else:
    MAX_REPLY_PHASE_SPAM_SCORE = 5

PGP_SENDER_PRIVATE_KEY = None
PGP_SENDER_PRIVATE_KEY_PATH = os.environ.get("PGP_SENDER_PRIVATE_KEY_PATH")
if PGP_SENDER_PRIVATE_KEY_PATH:
    with open(get_abs_path(PGP_SENDER_PRIVATE_KEY_PATH)) as f:
        PGP_SENDER_PRIVATE_KEY = f.read()

# the signer address that signs outgoing encrypted emails
PGP_SIGNER = os.environ.get("PGP_SIGNER")

# emails that have empty From address is sent from this special reverse-alias
NOREPLY = os.environ.get("NOREPLY", f"noreply@{EMAIL_DOMAIN}")

COINBASE_WEBHOOK_SECRET = os.environ.get("COINBASE_WEBHOOK_SECRET")
COINBASE_CHECKOUT_ID = os.environ.get("COINBASE_CHECKOUT_ID")
COINBASE_API_KEY = os.environ.get("COINBASE_API_KEY")
try:
    COINBASE_YEARLY_PRICE = float(os.environ["COINBASE_YEARLY_PRICE"])
except Exception:
    COINBASE_YEARLY_PRICE = 30.00

ALIAS_LIMIT = os.environ.get("ALIAS_LIMIT") or "100/day;50/hour;5/minute"

ENABLE_SPAM_ASSASSIN = "ENABLE_SPAM_ASSASSIN" in os.environ

ALIAS_RANDOM_SUFFIX_LENGTH = int(os.environ.get("ALIAS_RAND_SUFFIX_LENGTH", 5))

try:
    HIBP_SCAN_INTERVAL_DAYS = int(os.environ.get("HIBP_SCAN_INTERVAL_DAYS"))
except Exception:
    HIBP_SCAN_INTERVAL_DAYS = 7
HIBP_API_KEYS = sl_getenv("HIBP_API_KEYS", list) or []

NEWRELIC_CONFIG_PATH = os.environ.get("NEWRELIC_CONFIG_PATH")
