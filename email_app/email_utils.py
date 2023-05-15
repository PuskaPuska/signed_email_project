from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import imaplib
from email.mime.application import MIMEApplication
from email import message_from_bytes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Загрузка сертификата и закрытого ключа


def load_cert_and_private_key(cert, key, password):
    private_key = serialization.load_pem_private_key(
        key, password=password.encode(), backend=None
    )
    return cert, private_key

# Подписание письма с использованием закрытого ключа


def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature

# Функция для отправки писем


def send_signed_email(smtp_server, smtp_port, username, password, to, subject, body, cert, private_key, key_password):
    cert, private_key = load_cert_and_private_key(
        cert, private_key, key_password)

    # Подписание письма
    signature = base64.b64encode(sign_message(body, private_key))

    # Создание письма
    msg = MIMEMultipart()
    msg["From"] = username
    msg["To"] = to
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(cert.decode(), "plain"))
    msg.attach(MIMEText(signature.decode(), "plain"))

    # Отправка письма
    with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
        server.login(username, password)
        server.sendmail(username, to, msg.as_string())

# Загрузка открытого ключа


def load_public_key(cert):
    public_key = serialization.load_pem_public_key(cert, backend=None)
    return public_key

# Проверка подлинности подписи


def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print(e)
        return False

# Функция для чтения писем


def read_emails(imap_server, imap_port, username, password, cert):
    public_key = load_public_key(cert)

    # Подключение к почтовому серверу
    with imaplib.IMAP4_SSL(imap_server, imap_port) as server:
        server.login(username, password)
        server.select("inbox")

        # Получение списка писем
        _, message_numbers_raw = server.search(None, "ALL")
        message_numbers = message_numbers_raw[0].split()

        # Чтение последнего письма
        if message_numbers:
            _, msg_data = server.fetch(message_numbers[-1], "(RFC822)")
            msg = message_from_bytes(msg_data[0][1])

            # Проверка, является ли письмо многокомпонентным
            if msg.is_multipart():
                message_parts = []
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        raw_payload = part.get_payload(decode=True)
                        if raw_payload is not None:
                            message_parts.append(raw_payload.decode())
            else:
                raw_payload = msg.get_payload(decode=True)
                if raw_payload is not None:
                    message_parts = raw_payload.decode().split('\n\n')

            if len(message_parts) < 3:
                print("The message format is invalid.")
                return False

            message_body = message_parts[0]
            message_cert = message_parts[1]
            message_signature = base64.b64decode(message_parts[2])

            # Проверка подлинности подписи
            is_valid_signature = verify_signature(
                message_body, message_signature, public_key)
            return is_valid_signature
        else:
            return False




# Обработчик Django запросов


def send_email(request):
    if request.method == 'POST':
        form = SendEmailForm(request.POST, request.FILES)

        if form.is_valid():
            send_signed_email(
                form.cleaned_data['smtp_server'],
                form.cleaned_data['smtp_port'],
                form.cleaned_data['username'],
                form.cleaned_data['password'],
                form.cleaned_data['recipient'],
                form.cleaned_data['subject'],
                form.cleaned_data['body'],
                form.cleaned_data['cert'].read(),
                form.cleaned_data['private_key'].read(),
                form.cleaned_data['key_password'],
            )
            return HttpResponse('Email sent successfully')
    else:
        form = SendEmailForm()

    return render(request, 'email_app/send_email.html', {'form': form})
