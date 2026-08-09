from django.urls import path

from . import views

urlpatterns = [
    path("health", views.health),
    path("auth/<str:provider>/start", views.oauth_start),
    path("auth/<str:provider>/link", views.oauth_link_start),
    path("auth/<str:provider>/callback", views.oauth_callback),
    path("auth/ticket", views.exchange_ticket),
    path("auth/refresh", views.refresh),
    path("auth/logout", views.logout),
    path("me", views.me),
    path("me/account", views.delete_account),
    path("me/identities/<str:provider>", views.unlink_identity),
    path("mfa/entries", views.entries),
    path("mfa/entries/<int:entry_id>", views.entry_detail),
]
