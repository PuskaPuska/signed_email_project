from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .forms import SendEmailForm, ReadEmailForm
from .email_utils import send_signed_email, read_emails

@csrf_exempt
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

@csrf_exempt
def check_email(request):
    if request.method == 'POST':
        form = ReadEmailForm(request.POST, request.FILES)

        if form.is_valid():
            is_valid_signature = read_emails(
                form.cleaned_data['imap_server'],
                form.cleaned_data['imap_port'],
                form.cleaned_data['username'],
                form.cleaned_data['password'],
                form.cleaned_data['cert'].read(),
            )
            return HttpResponse(f'Email signature is valid: {is_valid_signature}')
    else:
        form = ReadEmailForm()

    return render(request, 'email_app/check_email.html', {'form': form})
