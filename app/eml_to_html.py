import email
from email import message_from_file
from email.message import Message
from pathlib import Path
import sys
from typing import Any, List, Union



def message_to_html_str(message: Message) -> str:
    payload: Any = message.get_payload()

    if isinstance(payload, str):
        payload_decoded: bytes = message.get_payload(decode=True)
        try:
            payload_decoded_str: str = payload_decoded.decode("ISO-8859-1")
        except UnicodeDecodeError:
            # try a different one
            payload_decoded_str: str = payload_decoded.decode("utf-8")

        return payload_decoded_str
    elif isinstance(payload, List):
        print(1)
        return "\n".join(
            [
                message_to_html_str(message)
                for message in payload
                if message.get_content_type() == "text/html"
            ]
        )
    else:
        raise ValueError(f"`payload` type is {type(payload)}")


def eml_to_message(eml_path_str: Union[str, Path]) -> Message:
    eml_path: Path = Path(eml_path_str)
    if not eml_path.is_file():
        print(f"🟡 Skipping `{eml_path}`; is not a file")

    if eml_path.suffix != ".eml":
        print(f"🟡 Skipping `{eml_path}`; not an .eml file")

    with eml_path.open(mode="r") as eml_file:
        message: Message = message_from_file(eml_file)
    return message








import quopri

textTypes  = [ 'text/plain', 'text/html' ]
imageTypes = [ 'image/gif', 'image/jpeg', 'image/png' ]


def _decode_subject(msg):
    try:
        decode = email.header.decode_header(msg['Subject'])[0]
        subjectField = str(decode[0])
    except:
        subjectField = '&lt;Unknown&gt;'
    return subjectField.replace('<', '&lt;').replace('>', '&gt;')

def message_to_rich_html(msg: Message):
    try:
        decode = email.header.decode_header(msg['Date'])[0]
        dateField = str(decode[0])
    except:
        dateField = '&lt;Unknown&gt;'

    try:
        decode = email.header.decode_header(msg['From'])[0]
        fromField = str(decode[0])
    except:
        fromField = '&lt;Unknown&gt;'
    fromField = fromField.replace('<', '&lt;').replace('>', '&gt;')

    try:
        decode = email.header.decode_header(msg['To'])[0]
        toField = str(decode[0])
    except:
        toField = '&lt;Unknown&gt;'
    toField = toField.replace('<', '&lt;').replace('>', '&gt;')

    subjectField = _decode_subject(msg)

    try:
        decode = email.header.decode_header(msg['Message-Id'])[0]
        idField = str(decode[0])
    except:
        idField = '&lt;Unknown&gt;'
    idField = idField.replace('<', '&lt;').replace('>', '&gt;')

    imgkitOptions = { 'load-error-handling': 'skip'}
    # imgkitOptions.update({ 'quiet': None })
    imagesList = []
    attachments = []

    # Build a first image with basic mail details
    headers = '''
    <table width="100%%">
      <tr><td align="right"><b>Date:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>From:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>To:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>Subject:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>Message-Id:</b></td><td>%s</td></tr>
    </table>
    <hr></p>
    ''' % (dateField, fromField, toField, subjectField, idField)
    import hashlib
    m = hashlib.md5()
    m.update(headers.encode('utf-8'))
    imagePath = m.hexdigest() + '.png'
    imagesList.append(headers)

    #
    # Main loop - process the MIME parts
    #
    for part in msg.walk():
        mimeType = part.get_content_type()
        if part.is_multipart():
            continue

        if mimeType in textTypes:
            try:
                payload = quopri.decodestring(part.get_payload(decode=True)).decode('utf-8')
            except:
                payload = str(quopri.decodestring(part.get_payload(decode=True)))[2:-1]

            # Cleanup dirty characters
            dirtyChars = [ '\n', '\\n', '\t', '\\t', '\r', '\\r']
            for char in dirtyChars:
                payload = payload.replace(char, '')

            # Generate MD5 hash of the payload
            m = hashlib.md5()
            m.update(payload.encode('utf-8'))
            imagePath = m.hexdigest() + '.png'
            imagesList.append(payload)

        elif mimeType in imageTypes:
            imagesList.append("<p>image data</p>")
            # payload = part.get_payload(decode=False)
            # imgdata = base64.b64decode(payload)
            # # Generate MD5 hash of the payload
            # m = hashlib.md5()
            # m.update(payload.encode('utf-8'))
            # imagePath = m.hexdigest() + '.' + mimeType.split('/')[1]
            # try:
            #     with open(dumpDir + '/' + imagePath, 'wb') as f:
            #         f.write(imgdata)
            #     writeLog('[INFO] Decoded %s' % imagePath)
            #     imagesList.append(dumpDir + '/' + imagePath)
            # except:
            #     writeLog('[WARNING] Decoding this MIME part returned error')
        else:
            fileName = part.get_filename()
            if not fileName:
                fileName = "Unknown"
            attachments.append("%s (%s)" % (fileName, mimeType))
            # writeLog('[INFO] Skipped attachment %s (%s)' % (fileName, mimeType))

    if len(attachments):
        footer = '<p><hr><p><b>Attached Files:</b><p><ul>'
        for a in attachments:
            footer = footer + '<li>' + a + '</li>'
        footer = footer + '</ul><p><br>Generated by EMLRender v1.0'
        m = hashlib.md5()
        m.update(footer.encode('utf-8'))
        imagePath = m.hexdigest() + '.png'
        imagesList.append(footer)

        # try:
        #     imgkit.from_string(footer, dumpDir + '/' + imagePath, options = imgkitOptions)
        #     writeLog('[INFO] Created footer %s' % imagePath)
        #     imagesList.append(dumpDir + '/' + imagePath)
        # except:
        #     writeLog('[WARNING] Creation of footer failed')

    return "".join(imagesList)
