import logging
import os

import phonenumbers
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.template import loader
from django.utils import timezone
from drfpasswordless.exceptions import DRFPwdlessValidationError
from drfpasswordless.models import CallbackToken
from drfpasswordless.settings import api_settings
from phonenumbers import NumberParseException
from twilio.base.exceptions import TwilioException, TwilioRestException
from twilio.rest import Client

logger = logging.getLogger('root')
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
    Sends an Email to user.email.
    Passes silently without sending in test environment.
    """
    try:
        # Make sure we have a sending address before sending.
        if not api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
            logger.debug("Failed to send token email. Missing PASSWORDLESS_EMAIL_NOREPLY_ADDRESS.")
            return False

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
            f"{email_plaintext}{email_token.key}",
            api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
            [getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)],
            fail_silently=False,
            html_message=html_message, )
        return True
    except Exception as e:
        logger.debug(
            f"Failed to send token email to user {user.id}. "
            f"Possibly no email on user object. The email entered was {getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)}.\n"
            f"Failed with error message: {e}")
        return False


def send_sms_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends a SMS to user.mobile via Twilio.
    Passes silently without sending in test environment.
    """
    if api_settings.PASSWORDLESS_TEST_SUPPRESSION:
        # Skip sending alert and assume success to prevent spamming WhatsApp messages during testing
        return True
    try:
        twilio_helper = TwilioHelper()
        base_string = kwargs.get('mobile_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)
        message_text = f"{base_string}{mobile_token.key}"
        twilio_helper.send_message(user=user, message_text=message_text)
        return True
    except (DRFPwdlessValidationError, TwilioRestException, TwilioException) as e:
        logger.error(
            f"Failed to send SMS to user {user}.\n"
            f"Failed with error message: {e}")
        return False


def send_whatsapp_message_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends a WhatsApp message to user.mobile via Twilio.
    Passes silently without sending in test environment.
    """
    if api_settings.PASSWORDLESS_TEST_SUPPRESSION:
        # Skip sending alert and assume success to prevent spamming WhatsApp messages during testing
        return True
    try:
        twilio_helper = TwilioHelper()
        base_string = kwargs.get('whatsapp_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)
        message_text = f"{base_string}{mobile_token.key}"
        twilio_helper.send_message(user=user, message_text=message_text, is_whatsapp=True)
        return True
    except (DRFPwdlessValidationError, TwilioRestException, TwilioException) as e:
        logger.error(
            f"Failed to send WhatsApp message to user {user}.\n"
            f"Failed with error message: {e}")
        return False


class TwilioHelper(object):
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
    USER_MOBILE_FIELD_NAME = 'mobile'
    twilio_number = ''
    twilio_client = None

    def __init__(self):
        try:
            self.twilio_client = Client(self.TWILIO_ACCOUNT_SID, self.TWILIO_AUTH_TOKEN)
        except TwilioException as e:
            logger.error("Failed to create Twilio client. Please check your Twilio environment settings.\n"
                         f"Failed with error message: {e}")
            raise

        # Retrieve Twilio number from configuration and validate
        self.twilio_number = getattr(api_settings, 'PASSWORDLESS_MOBILE_NOREPLY_NUMBER')
        try:
            p = self.str_to_phonenumber(self.twilio_number)
            self.validate_phone(p)
        except DRFPwdlessValidationError as e:
            raise DRFPwdlessValidationError(f"Invalid Twilio number - {e}")

    def send_message(self, user, message_text, is_whatsapp=False):
        # Retrieve user number and validate
        to_number = getattr(user, self.USER_MOBILE_FIELD_NAME)
        self.validate_phone(to_number)
        from_number = self.twilio_number

        if is_whatsapp:
            to_number = f"whatsapp:{to_number}"
            from_number = f"whatsapp:{from_number}"
        try:
            res = self.twilio_client.messages.create(
                body=message_text,
                to=to_number,
                from_=from_number
            )
            logger.info(res)
        except TwilioRestException as e:
            logger.error(
                f"Failed to message user {user.id}, with number {to_number}.\n"
                f"Failed with error message: {e}")
            raise

    @staticmethod
    def str_to_phonenumber(phonestr):
        """
        Converts a str to phone number object.
        Throws DRFPwdlessValidationError if the number could not be parsed.
        """
        try:
            return phonenumbers.parse(phonestr)
        except NumberParseException as e:
            logger.error(e)
            raise DRFPwdlessValidationError(e)

    @staticmethod
    def validate_phone(phoneobj):
        """
        Tests whether a phone number is valid.
        Arguments:
        phoneobj -- The phone number object

        Throws DRFPwdlessValidationsError if the number is not valid.
        """
        if not phonenumbers.is_valid_number(phoneobj):
            raise DRFPwdlessValidationError("Invalid phone number")
