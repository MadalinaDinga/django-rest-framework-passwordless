from django.contrib import admin
from django.urls import reverse
from drfpasswordless.models import CallbackToken
from django.forms.models import BaseInlineFormSet


class UserLinkMixin(object):
    """
    A mixin to add a linkable list_display user field.
    """
    LINK_TO_USER_FIELD = 'link_to_user'

    def link_to_user(self, obj):
        link = reverse('admin:users_user_change', args=[obj.user.id])
        return u'<a href={}>{}</a>'.format(link, obj.user.username)
    link_to_user.allow_tags = True
    link_to_user.short_description = 'User'


class AbstractCallbackTokenInline(admin.TabularInline):
    max_num = 0
    extra = 0
    readonly_fields = ('created_at', 'key', 'is_active')
    fields = ('created_at', 'user', 'key', 'is_active')
    ordering = ('-created_at',)


class CallbackInline(AbstractCallbackTokenInline):
    model = CallbackToken


class ActiveCallbackInline(AbstractCallbackTokenInline):
    model = CallbackToken

    def get_queryset(self, request):
        qs = super(ActiveCallbackInline, self).get_queryset(request).filter(is_active=True)
        return qs


class AbstractCallbackTokenAdmin(UserLinkMixin, admin.ModelAdmin):
    readonly_fields = ('created_at', 'user', 'key')
    list_display = ('created_at', UserLinkMixin.LINK_TO_USER_FIELD, 'key', 'is_active')
    fields = ('created_at', 'user', 'key', 'is_active')
    extra = 0
