"""
license...
"""
import os
import sys
import logging
from datetime import timedelta
from django.contrib.messages import constants as messages

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

log = logging.getLogger(__name__)

BROKER_URL = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

CELERYBEAT_SCHEDULE = {
    'update-progress-counts': {
        'task': 'scanner.tasks.update_progress_counts',
        'schedule': timedelta(seconds=300)
    },
    'cleanup-completed-scans': {
        'task': 'scanner.tasks.cleanup_completed_scans',
        'schedule': timedelta(seconds=120)
    },
    'load-job-queues': {
        'task': 'scanner.tasks.load_job_queues',
        'schedule': timedelta(seconds=60)
    },
    'update-completion-dates': {
        'task': 'scanner.tasks.update_completion_dates',
        'schedule': timedelta(seconds=3600)
    }
}

config = configparser.ConfigParser()
config.read(os.path.join(os.path.expanduser('~'), ".portplow.conf"))

EXTERNAL_IP = config.get("external", "ip")
EXTERNAL_PORT = config.get("external", "port")
DOMAIN = config.get("external", "domain")
SITE_NAME = config.get("internal", "site_name")

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


SECRET_KEY = config.get("internal", "secret_key")
DEBUG = False

ALLOWED_HOSTS = [DOMAIN, '0.0.0.0', EXTERNAL_IP]

MAX_JOB_RETRIES = 10

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_extensions',
    'rest_framework',
    'rest_framework.authtoken',
    'bootstrap3',
    'crispy_forms',
    'scanner',
    'api',
    'utils',
    'session_security',
]

MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware', 
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'session_security.middleware.SessionSecurityMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'portplow.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')]
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                "django.core.context_processors.request",
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # 'django.contrib.auth.context_processors.PermWrapper',
            ],
        },
    },
]

WSGI_APPLICATION = 'portplow.wsgi.application'

DATABASES = {
    # 'default': {
    #     'ENGINE': 'django.db.backends.sqlite3',
    #     'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    # }
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': config.get("database", "database"),
        'USER': config.get("database", "user"),
        'PASSWORD': config.get("database", "password"),
        'HOST': 'localhost',
        'PORT': ''
    }

}

MESSAGE_TAGS = {
    messages.ERROR: 'danger'
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = False

STATIC_URL = '/static/'
STATICFILES_FINDERS = ["django.contrib.staticfiles.finders.FileSystemFinder",
                       "django.contrib.staticfiles.finders.AppDirectoriesFinder"]

STATIC_ROOT = '/opt/portplow/static'

REST_FRAMEWORK = {
    'DEFAULT_MODEL_SERIALIZER_CLASS': 'rest_framework.serializers.ModelSerializer',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    # 'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAdminUser',),
    'PAGE_SIZE': 100
}


# Attempt to get DigitalOcean keys from environment
DO_USERNAME = os.environ.get("PORTPLOW_DOUSER", "portplow")
try:
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.expanduser('~'), ".portplow.conf"))
    DO_APIKEY = os.environ.get("PORTPLOW_DOAPIKEY", None)
    if DO_APIKEY is None:
        DO_APIKEY = config.get("digitalocean", "api_key")
except configparser.NoSectionError:
    log.error("~/.portplow.conf is missing the [digitalocean] section.")
    sys.exit(1)
except configparser.NoOptionError:
    log.error("~/.portplow.conf is missing the 'api_key =' option.")
    sys.exit(1)

# print("API key: {}".format(DO_APIKEY))

CLIENT_OUTPUT_DIR = "/var/opt/portplow/results"
CLIENT_DELAY = 3

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        # 'file': {
        #     'level': 'DEBUG',
        #     'class': 'logging.FileHandler',
        #     'filename': 'logs/portplow.log',
        #     'formatter': 'verbose'
        # },
        # 'dbfile': {
        #     'level': 'DEBUG',
        #     'class': 'logging.FileHandler',
        #     'filename': 'logs/database-queries.log',
        #     'formatter': 'verbose'
        # },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'loggers': {
        'django': {
            'handlers': [
                # 'file',
                'console'
            ],
            'propagate': True,
        },
        # 'django.db.backends': {
        #     'handlers': ['dbfile'],
        #     'level': 'DEBUG',
        # },
    },
}

LOGIN_URL = '/portplow/login'
LOGIN_REDIRECT_URL = '/portplow/'

CRISPY_TEMPLATE_PACK = 'bootstrap3'

EMAIL_USE_TLS = config.get("email", "use_tls")
DEFAULT_FROM_EMAIL = config.get("email", "from_email")
SERVER_EMAIL = config.get("email", "server_email")
EMAIL_HOST = config.get("email", "host")
EMAIL_PORT = config.get("email", "port")
EMAIL_HOST_USER = config.get("email", "user")
EMAIL_HOST_PASSWORD = config.get("email", "password")
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

'''
use_tls = True
from_email = 'support@portplow.io'
server_email = 'support@portplow.io'
host = 'mail.privateemail.com'
port = 26
user = 'support@portplow.io'
password = '--email-password--'
'''

# def show_toolbar(request):
#     # print("Checking if we should show the toolbar. User:{}".format(request.user))
#     return not request.is_ajax() and request.user.username == "drush"
#
# DEBUG_TOOLBAR_CONFIG = {
#     'SHOW_TOOLBAR_CALLBACK': 'portplow.settings.show_toolbar',
# }
#
# DEBUG_TOOLBAR_PANELS = [
#     # 'debug_toolbar.panels.versions.VersionsPanel',
#     'debug_toolbar.panels.timer.TimerPanel',
#     'debug_toolbar.panels.settings.SettingsPanel',
#     'debug_toolbar.panels.headers.HeadersPanel',
#     'debug_toolbar.panels.request.RequestPanel',
#     'debug_toolbar.panels.sql.SQLPanel',
#     # 'debug_toolbar.panels.staticfiles.StaticFilesPanel',
#     'debug_toolbar.panels.templates.TemplatesPanel',
#     'debug_toolbar.panels.cache.CachePanel',
#     'debug_toolbar.panels.signals.SignalsPanel',
#     'debug_toolbar.panels.logging.LoggingPanel',
#     'debug_toolbar.panels.redirects.RedirectsPanel',
# ]

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": BROKER_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

SESSION_SECURITY_WARN_AFTER = 540
SESSION_SECURITY_EXPIRE_AFTER = 600
