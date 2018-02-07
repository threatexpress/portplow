from django.conf.urls import url
from utils.views import ResetPasswordRequestView, PasswordResetConfirmView, logout, UserAddView

urlpatterns = [
    url(r'^reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', PasswordResetConfirmView.as_view(),
        name='reset_password_confirm'),
    url(r'^reset_password', ResetPasswordRequestView.as_view(), name="reset_password"),
    url(r'^user/add', UserAddView.as_view(), name="add_user"),
    # url(r'^logout', logout, name="logout")
    ]
