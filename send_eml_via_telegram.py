import requests
import os
import base64
import email
import email.header
import quopri
import os
from email import policy
from email.message import Message

from collections import defaultdict
from typing import Dict, Union, Tuple
import traceback

# TELEPUSH_BASE_URL = "https://telepush.dev/api/messages"
# TELEPUSH_TOKEN = os.getenv("TELEPUSH_TOKEN")
# if not TELEPUSH_TOKEN:
#     raise ValueError("The environment variable ${TELEPUSH_TOKEN} needs to be set!")
# TELEPUSH_ENDPOINT = f"{TELEPUSH_BASE_URL}/{TELEPUSH_TOKEN}"


TELEPUSH_BASE_URL = "https://api.telegram.org"
TELEGRAM_BOT_SIMPLE_LOGIN_TOKEN = os.getenv("TELEGRAM_BOT_SIMPLE_LOGIN_TOKEN")
if not TELEGRAM_BOT_SIMPLE_LOGIN_TOKEN:
    raise ValueError(
        "The environment variable ${TELEGRAM_BOT_SIMPLE_LOGIN_TOKEN} needs to be set!"
    )

TELEGRAM_BOT_SIMPLE_LOGIN_CHAT_ID = os.getenv(
    "TELEGRAM_BOT_SIMPLE_LOGIN_CHAT_ID", "6063324853"
)
_width, _height = 1000, 900
HTML2IMG_ENDPOINT = os.getenv("HTML2IMG_ENDPOINT", "http://127.0.0.1:8080/html2image")
HTML2IMG_ENDPOINT = f"{HTML2IMG_ENDPOINT}?w={_width}&h={_height}"
TELEPUSH_ENDPOINT = f"{TELEPUSH_BASE_URL}/bot{TELEGRAM_BOT_SIMPLE_LOGIN_TOKEN}"


textTypes = ["text/plain", "text/html"]
imageTypes = ["image/gif", "image/jpeg", "image/png"]


def html_sanitise(text: Union[str, bytes]) -> str:
    if type(text) == bytes:
        text = text.decode()
    return text.replace("<", "&lt;").replace(">", "&gt;")


def header_decode(header) -> str:
    hdr = ""
    for text, encoding in email.header.decode_header(header):
        if isinstance(text, bytes):
            text = text.decode(encoding or "us-ascii")
        hdr += text
    return hdr


def message_to_bytes(msg: Message) -> bytes:
    """replace Message.as_bytes() method by trying different policies"""
    for generator_policy in [None, policy.SMTP, policy.SMTPUTF8]:
        try:
            return msg.as_bytes(policy=generator_policy)
        except:
            print(f"as_bytes() fails with {policy} policy")

    msg_string = msg.as_string()
    try:
        return msg_string.encode()
    except:
        print("as_string().encode() fails")

    return msg_string.encode(errors="replace")


def extract_message_as_html_str(message: Message) -> str:
    payload = message.get_payload()

    if isinstance(payload, str):
        payload_decoded: bytes = message.get_payload(decode=True)
        payload_decoded_str: str = payload_decoded.decode("utf-8")
        return payload_decoded_str
    elif isinstance(payload, list):
        return "\n".join(
            [
                extract_message_as_html_str(message)
                for message in payload
                if message.get_content_type() == "text/html"
            ]
        )
    else:
        return "[failed to parse message]"
        # raise ValueError(f"`payload` type is {type(payload)}")


def extract_datapack(msg: Message) -> Dict:
    datapack = dict()
    try:
        datapack["date"] = header_decode(msg["Date"])
    except:
        pass

    try:
        datapack["from"] = header_decode(msg["From"])
    except:
        pass

    try:
        datapack["to"] = header_decode(msg["To"])
    except:
        pass

    try:

        datapack["subject"] = header_decode(msg["Subject"])
    except:
        pass

    try:
        datapack["id"] = header_decode(msg["Message-Id"])
    except:
        pass

    return datapack


def datapack_to_pretty_header(datapack: Dict) -> str:
    unknown = "&lt;Unknown&gt;"
    # Build a first image with basic mail details
    return f"""
    <table width="100%">
      <tr><td align="right"><b>Date:</b></td><td>{datapack.get('date', unknown)}</td></tr>
      <tr><td align="right"><b>From:</b></td><td>{html_sanitise(datapack.get('from', unknown))}</td></tr>
      <tr><td align="right"><b>To:</b></td><td>{html_sanitise(datapack.get('to', unknown))}</td></tr>
      <tr><td align="right"><b>Subject:</b></td><td>{html_sanitise(datapack.get('subject', unknown))}</td></tr>
      <tr><td align="right"><b>Message-Id:</b></td><td>{html_sanitise(datapack.get('id', unknown))}</td></tr>
    </table>
    <hr></p>
    """


def processEml(msg: Message) -> Tuple[str, Dict]:
    """
    Process the email (bytes), extract MIME parts and useful headers.
    Generate a PNG picture of the mail
    """
    datapack = extract_datapack(msg)
    header = datapack_to_pretty_header(datapack)

    return f"{header}{extract_message_as_html_str(msg)}", datapack


def processEml_brute(msg: Message) -> Tuple[str, Dict]:

    """
    Process the email (bytes), extract MIME parts and useful header.
    Generate a PNG picture of the mail
    """
    # Build a first image with basic mail details

    datapack = extract_datapack(msg)
    header = datapack_to_pretty_header(datapack)

    html_parts = []
    attachments = []

    html_parts.append(header)

    #
    # Main loop - process the MIME parts
    #
    for part in msg.walk():
        mimeType = part.get_content_type()
        if part.is_multipart():
            continue

        if mimeType in textTypes:
            try:
                payload = quopri.decodestring(part.get_payload(decode=True)).decode(
                    "utf-8"
                )
            except:
                payload = str(quopri.decodestring(part.get_payload(decode=True)))[2:-1]

            # Cleanup dirty characters
            dirtyChars = ["\n", "\\n", "\t", "\\t", "\r", "\\r"]
            for char in dirtyChars:
                payload = payload.replace(char, "")

            html_parts.append(payload)
        # elif mimeType in imageTypes:
        #     payload = part.get_payload(decode=False)
        #     imgdata = base64.b64decode(payload)
        #     # Generate MD5 hash of the payload
        #     m = hashlib.md5()
        #     m.update(payload.encode('utf-8'))
        #     imagePath = m.hexdigest() + '.' + mimeType.split('/')[1]

        #     # with open(dumpDir / imagePath, 'wb') as f:
        #     #     f.write(imgdata)
        #     # html_parts.append(dumpDir / imagePath)
        else:
            fileName = part.get_filename()
            if not fileName:
                fileName = "Unknown"
            attachments.append("%s (%s)" % (fileName, mimeType))

    if len(attachments):
        footer = "<p><hr><p><b>Attached Files:</b><p><ul>"
        for a in attachments:
            footer = footer + "<li>" + a + "</li>"
        footer = footer + "</ul><p><br>Generated by EMLRender v1.0"
        html_parts.append(footer)

    return "".join(html_parts), datapack


def get_default_payload() -> Dict:
    return dict(
        parse_mode="Markdown",
        chat_id=TELEGRAM_BOT_SIMPLE_LOGIN_CHAT_ID,
        disable_notification=False,
    )


def _send_eml_to_telegram(*, eml_msg: Message = None, msg_as_bytes: bytes = None):
    assert bool(eml_msg) or bool(msg_as_bytes)
    if eml_msg is None:
        eml_msg = email.message_from_bytes(msg_as_bytes)
    if msg_as_bytes is None:
        msg_as_bytes = message_to_bytes(eml_msg)

    def send_img_msg(msg: str, image_bytes):
        payload = get_default_payload()
        payload["caption"] = msg
        r = requests.post(
            f"{TELEPUSH_ENDPOINT}/sendPhoto",
            data=payload,
            files=(("photo", ("screenshot.png", image_bytes)),),
        )
        if r.status_code != 200:
            print(r.text)

    def send_text_msg(msg: str, error_msg: str):
        payload = get_default_payload()
        payload["text"] = f"{msg}\n> Failed to generate image:\n{error_msg}"
        r = requests.post(
            f"{TELEPUSH_ENDPOINT}/sendMessage",
            data=payload,
        )
        if r.status_code != 200:
            print(r.text)

    def send_docunment(date: str, subject: str):
        payload = get_default_payload()
        payload["disable_notification"] = True
        # payload['caption'] = msg
        r = requests.post(
            f"{TELEPUSH_ENDPOINT}/sendDocument",
            data=payload,
            files=(("document", (f"[{date}] {subject}.eml", msg_as_bytes)),),
        )
        if r.status_code != 200:
            print(r.text)

    data, _datapack = processEml(eml_msg)
    datapack = defaultdict(lambda: "[empyt]")
    datapack.update(_datapack)
    if "from" in _datapack:
        _date = " ".join(_datapack["date"].split(" ")[1:5])
    else:
        _date = "[empty]"
    msg = (
        f"*{datapack['subject']}*\n\n"
        f"_Date: {_date}_\n"
        f"From: {datapack['from']}\n"
        f"To: {datapack['to']}\n"
    )

    r = requests.post(HTML2IMG_ENDPOINT, data=data.encode("utf-8"))
    if r.status_code == 200 and r.headers["Content-Type"].startswith("image/"):
        send_img_msg(msg, r.content)
    else:
        print(r.status_code, r.text)
        send_text_msg(msg, error_msg=r.text)
    send_docunment(_date, datapack["subject"])


def send_eml_to_telegram(**kwargs):
    try:
        _send_eml_to_telegram(**kwargs)
    except Exception as e:
        print(traceback.format_exc())


if __name__ == "__main__":
    with open("./mail.eml", "rb") as f:
        # file_content_bytes = f.read()
        send_eml_to_telegram(msg_as_bytes=f.read())
