import logging
import os

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.template import loader
from django.utils import timezone
from drfpasswordless.models import CallbackToken
from drfpasswordless.settings import api_settings
from twilio.rest import Client

logger = logging.getLogger(__name__)
User = get_user_model()


def authenticate_by_token(callback_token, email=None, mobile=None):
    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True)

        token_user = User.objects.get(pk=token.user.pk)
        if email:
            to_verify_user = User.objects.get(email=email)
        elif mobile:
            to_verify_user = User.objects.get(mobile=mobile)
        else:
            return None

        if token_user.id == to_verify_user.id:
            # Returning a user designates a successful authentication.
            token.user = token_user
            token.is_active = False  # Mark this token as used.
            token.save()

            return token.user

    except CallbackToken.DoesNotExist:
        logger.debug("drfpasswordless: Challenged with a callback token that doesn't exist.")
    except User.DoesNotExist:
        logger.debug("drfpasswordless: Authenticated user somehow doesn't exist.")
    except PermissionDenied:
        logger.debug("drfpasswordless: Permission denied while authenticating.")

    return None


def create_callback_token_for_user(user, token_type):
    token = None
    token_type = token_type.upper()

    if token_type == 'EMAIL':
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME))
    elif token_type in ['MOBILE', 'WHATSAPP']:
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME))
    if token is not None:
        return token

    return None


def validate_token_age(callback_token):
    """
    Returns True if a given token is within the age expiration limit.
    """
    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True)
        seconds = (timezone.now() - token.created_at).total_seconds()
        token_expiry_time = api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME

        if seconds <= token_expiry_time:
            return True
        else:
            # Invalidate our token.
            token.is_active = False
            token.save()
            return False

    except CallbackToken.DoesNotExist:
        # No valid token.
        return False


def verify_user_alias(user, token):
    """
    Marks a user's contact point as verified depending on accepted token type.
    """
    if token.to_alias_type == 'EMAIL':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, True)
    elif token.to_alias_type in ['MOBILE', 'WHATSAPP']:
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME, True)
    else:
        return False
    user.save()
    return True


def inject_template_context(context):
    """
    Injects additional context into email template.
    """
    for processor in api_settings.PASSWORDLESS_CONTEXT_PROCESSORS:
        context.update(processor())
    return context


def send_email_with_callback_token(user, email_token, **kwargs):
    """
    Sends a Email to user.email.

    Passes silently without sending in test environment
    """

    try:
        if api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
            # Make sure we have a sending address before sending.

            # Get email subject and message
            email_subject = kwargs.get('email_subject',
                                       api_settings.PASSWORDLESS_EMAIL_SUBJECT)
            email_plaintext = kwargs.get('email_plaintext',
                                         api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE)
            email_html = kwargs.get('email_html',
                                    api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME)

            # Inject context if user specifies.
            context = inject_template_context({'callback_token': email_token.key, })
            html_message = loader.render_to_string(email_html, context, )
            send_mail(
                email_subject,
                email_plaintext % email_token.key,
                api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
                [getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)],
                fail_silently=False,
                html_message=html_message, )

        else:
            logger.debug("Failed to send token email. Missing PASSWORDLESS_EMAIL_NOREPLY_ADDRESS.")
            return False
        return True

    except Exception as e:
        logger.debug("Failed to send token email to user: %d."
                     "Possibly no email on user object. Email entered was %s" %
                     (user.id, getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)))
        logger.debug(e)
        return False


def send_sms_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends a SMS to user.mobile via Twilio.

    Passes silently without sending in test environment.
    """
    base_string = kwargs.get('mobile_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)

    try:

        if api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER:
            # We need a sending number to send properly
            if api_settings.PASSWORDLESS_TEST_SUPPRESSION:
                # we assume success to prevent spamming SMS during testing.
                return True

            twilio_client = Client(os.environ['TWILIO_ACCOUNT_SID'], os.environ['TWILIO_AUTH_TOKEN'])

            to_number = getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)
            if to_number.__class__.__name__ == 'PhoneNumber':
                to_number = to_number.__str__()

            twilio_client.messages.create(
                body=base_string % mobile_token.key,
                to=to_number,
                from_=api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER
            )
            return True
        else:
            logger.debug("Failed to send token sms. Missing PASSWORDLESS_MOBILE_NOREPLY_NUMBER.")
            return False
    except ImportError:
        logger.debug("Couldn't import Twilio client. Is twilio installed?")
        return False
    except KeyError:
        logger.debug("Couldn't send SMS."
                     "Did you set your Twilio account tokens and specify a PASSWORDLESS_MOBILE_NOREPLY_NUMBER?")
    except Exception as e:
        logger.debug("Failed to send token SMS to user: {}. "
                     "Possibly no mobile number on user object or the twilio package isn't set up yet. "
                     "Number entered was {}".format(user.id,
                                                    getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)))
        logger.debug(e)
        return False


def send_whatsapp_message_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends a WhatsApp message to user.mobile via Twilio.

    Passes silently without sending in test environment.
    """
    base_string = kwargs.get('whatsapp_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)

    try:
        if api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER:
            # We need a sending number to send properly
            if api_settings.PASSWORDLESS_TEST_SUPPRESSION:
                # we assume success to prevent spamming WhatsApp messages during testing.
                return True

            twilio_client = Client(os.environ['TWILIO_ACCOUNT_SID'], os.environ['TWILIO_AUTH_TOKEN'])

            # The number where the token will be sent via WhatsApp
            to_whatsapp_number = getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)
            if to_whatsapp_number.__class__.__name__ == 'PhoneNumber':
                to_whatsapp_number = f"whatsapp:{to_whatsapp_number.__str__()}"

            # The number sending the token via WhatsApp (the Twilio Sandbox)
            from_whatsapp_number = f"whatsapp:{api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER}"

            try:
                twilio_client.messages.create(
                    body=f"{base_string}{mobile_token.key}",
                    to=to_whatsapp_number,
                    from_=from_whatsapp_number
                )
            except Exception as e:
                print(e)
                raise
            finally:
                return True
        else:
            logger.debug("Failed to send token sms. Missing PASSWORDLESS_MOBILE_NOREPLY_NUMBER.")
            return False
    except ImportError:
        logger.debug("Couldn't import Twilio client. Is Twilio installed?")
        return False
    except KeyError:
        logger.debug("Couldn't send SMS."
                     "Did you set your Twilio account tokens and specify a PASSWORDLESS_MOBILE_NOREPLY_NUMBER?")
    except Exception as e:
        logger.debug("Failed to send token SMS to user: {}. "
                     "Possibly no mobile number on user object or the twilio package isn't set up yet. "
                     "Number entered was {}".format(user.id,
                                                    getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)))
        logger.debug(e)
        return False
