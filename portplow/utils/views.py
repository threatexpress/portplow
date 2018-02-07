import logging
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from portplow.settings import DEFAULT_FROM_EMAIL
from django.views.generic import *
from utils.forms import PasswordResetRequestForm, SetPasswordForm, UserForm
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.shortcuts import HttpResponseRedirect, resolve_url
from django.db.models.query_utils import Q
from portplow.settings import LOGIN_URL, DOMAIN, SITE_NAME
from scanner.models import Group, generate_random_password
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required, user_passes_test

User = get_user_model()


class ResetPasswordRequestView(FormView):
    template_name = "utils/password_reset_form-utils.html"
    success_url = LOGIN_URL
    form_class = PasswordResetRequestForm
    log = logging.getLogger(__name__)

    @staticmethod
    def validate_email_address(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        self.log.debug("Received a post.")
        try:
            if form.is_valid():
                data = form.cleaned_data["email_or_username"]

                if self.validate_email_address(data) is True:
                    '''
                    If the input is an valid email address, then the following code will lookup for users associated with
                    that email address. If found then an email will be sent to the address, else an error message will be
                    printed on the screen.
                    '''
                    self.log.debug("Email is valid.")
                    associated_users = User.objects.filter(Q(email=data)|Q(username=data))
                    if associated_users.exists():
                        self.log.debug("The user exists.")
                        for user in associated_users:
                            c = {
                                'email': user.email,
                                'domain': request.META['HTTP_HOST'],
                                'site_name': 'your site',
                                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                'user': user,
                                'token': default_token_generator.make_token(user),
                                'protocol': 'https',
                                }
                            subject_template_name='registration/password_reset_subject.txt'
                            email_template_name='utils/password_reset_email-utils.html'
                            subject = loader.render_to_string(subject_template_name, c)
                            subject = ''.join(subject.splitlines())
                            email = loader.render_to_string(email_template_name, c)
                            self.log.debug("Ready to send email. {}".format(email))
                            send_mail(subject, email, DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
                            self.log.debug("Email has been sent.")
                        result = self.form_valid(form)
                        messages.success(request, 'An email has been sent to ' + data + ". Please check its inbox to continue reseting password.")
                        self.log.debug("Finished request. Result: {}".format(result))
                        return result
                    else:
                        result = self.form_invalid(form)
                        messages.error(request, 'Username or Email not found.')
                        return result
                else:
                    '''
                    If the input is an username, then the following code will lookup for users associated with that user.
                    If found then an email will be sent to the user's address, else an error message will be printed on
                    the screen.
                    '''
                    associated_users = User.objects.filter(username=data)
                    if associated_users.exists():
                        for user in associated_users:
                            c = {
                                'email': user.email,
                                'domain': DOMAIN,
                                'site_name': SITE_NAME,
                                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                'user': user,
                                'token': default_token_generator.make_token(user),
                                'protocol': 'https',
                                }
                            subject_template_name='registration/password_reset_subject.txt'
                            email_template_name='utils/password_reset_email-utils.html'
                            subject = loader.render_to_string(subject_template_name, c)
                            # Email subject *must not* contain newlines
                            subject = ''.join(subject.splitlines())
                            email = loader.render_to_string(email_template_name, c)
                            send_mail(subject, email, DEFAULT_FROM_EMAIL , [user.email], fail_silently=False)
                        result = self.form_valid(form)
                        messages.success(request, 'Email has been sent to ' + data +"'s email address. Please check its inbox to continue reseting password.")
                        return result
                    result = self.form_invalid(form)
                    messages.error(request, 'Username or email not found.')
                    return result

            messages.error(request, 'Invalid Input')

        except Exception as e:
            self.log.error(e)

        return self.form_invalid(form)


class PasswordResetConfirmView(FormView):
    template_name = "utils/password_reset_form-utils.html"
    success_url = '/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password = form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(request,'The reset password link is no longer valid.')
            return self.form_invalid(form)



# @method_decorator(user_passes_test, lambda u: u.is_superuser)
@method_decorator(login_required, name="dispatch")
class UserAddView(FormView):
    template_name = "utils/user_add_form.html"
    form_class = UserForm
    success_url = '/portplow/users'

    def post(self, request, *args, **kwargs):
        UserModel = get_user_model()
        form = self.form_class(request.POST or None)
        if form.is_valid():
            user = form.save(commit=False)
            user.password = generate_random_password()
            user.save()
            user.refresh_from_db()
            user.groups.add(Group.objects.first())
            user.save()
            return self.form_valid(form)
        else:
            messages.error(request, "Invalid information provided.")
            return self.form_invalid(form)


def logout_view(request):
    logout(request)
    return HttpResponseRedirect("/")
