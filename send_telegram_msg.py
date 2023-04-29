import requests
import os
import base64


TELEPUSH_BASE_URL = "https://telepush.dev/api/messages"
TELEPUSH_TOKEN = os.getenv("TELEPUSH_TOKEN")
if not TELEPUSH_TOKEN:
    raise ValueError("The environment variable ${TELEPUSH_TOKEN} needs to be set!")
TELEPUSH_ENDPOINT = f"{TELEPUSH_BASE_URL}/{TELEPUSH_TOKEN}"


def send_telegram_msg(
    msg: str,
    origin: str = None,
    file_on_disk: str = None,
    filename: str = None,
    base64_encoded_file: str = None,
):
    if all(v is not None for v in (base64_encoded_file, file_on_disk)):
        raise ValueError("mutually exclusive argunments")

    payload = dict(text=msg)
    if origin is not None:
        payload["origin"] = origin
    requests.post(TELEPUSH_ENDPOINT, json=payload)

    #########################################
    # *reusing previous payload
    if file_on_disk is not None:
        with open(file_on_disk, "rb") as f:
            base64_encoded_file = base64.b64encode(f.read())
        filename = file_on_disk if filename is None else filename

    if base64_encoded_file is not None:
        payload["type"] = "FILE"
        payload["file"] = base64_encoded_file
        if filename is not None:
            payload["filename"] = filename

        requests.post(TELEPUSH_ENDPOINT, json=payload)


# send_telegram_msg(
#     "hi",
#     origin="simplelogin",
#     filename="haha.zip",
#     # file_on_disk="/home/tin/clion-settings.zip"
#     base64_encoded_file=base64.b64encode(open("/home/tin/clion-settings.zip", 'rb').read())
# )

