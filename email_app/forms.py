from django import forms


class SendEmailForm(forms.Form):
    smtp_server = forms.CharField(label='SMTP server', max_length=100)
    smtp_port = forms.IntegerField(label='SMTP port', min_value=1, max_value=65535)
    username = forms.EmailField(label='Email address')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    recipient = forms.EmailField(label='Recipient')
    subject = forms.CharField(label='Subject', max_length=100)
    body = forms.CharField(label='Body', widget=forms.Textarea)
    cert = forms.FileField(label='Certificate')
    private_key = forms.FileField(label='Private key')
    key_password = forms.CharField(label='Key password', widget=forms.PasswordInput)


class ReadEmailForm(forms.Form):
    imap_server = forms.CharField(label='IMAP server', max_length=100)
    imap_port = forms.IntegerField(label='IMAP port', min_value=1, max_value=65535)
    username = forms.EmailField(label='Email address')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    cert = forms.FileField(label='Public key')