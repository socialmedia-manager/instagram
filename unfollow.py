import json
import codecs
import datetime
import os.path
import logging
import argparse
import re
try:
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)
except ImportError:
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)


def to_json(python_object):
    if isinstance(python_object, bytes):
        return {'__class__': 'bytes',
                '__value__': codecs.encode(python_object, 'base64').decode()}
    raise TypeError(repr(python_object) + ' is not JSON serializable')


def from_json(json_object):
    if '__class__' in json_object and json_object['__class__'] == 'bytes':
        return codecs.decode(json_object['__value__'].encode(), 'base64')
    return json_object


def onlogin_callback(api, new_settings_file):
    cache_settings = api.settings
    with open(new_settings_file, 'w') as outfile:
        json.dump(cache_settings, outfile, default=to_json)
        logger.info('Saved log in information: {0!s}'.format(new_settings_file))


def login():
    '''
    Login and save credentials avoiding re-login.

    You are advised to persist/cache the auth cookie 
    details to avoid logging in every time you make 
    an api call. Excessive logins is a surefire way 
    to get your account flagged for removal. It's 
    also advisable to cache the client details such 
    as user agent, etc together with the auth details.
    The saved auth cookie can be reused for up to 
    90 days.
    '''
    
    parser = argparse.ArgumentParser(description='login callback and save settings demo')
    parser.add_argument('-settings', '--settings', dest='settings_file_path', type=str, required=False)
    parser.add_argument('-u', '--username', dest='username', type=str, required=False)
    parser.add_argument('-p', '--password', dest='password', type=str, required=False)
    parser.add_argument('-debug', '--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info('Client version: {0!s}'.format(client_version))

    device_id = None

    try:
        settings_file = args.settings_file_path

        if not os.path.isfile(settings_file):
            logger.info('Unable to find file: {0!s}'.format(settings_file))

            api = Client(
                args.username, args.password,
                on_login=lambda x: onlogin_callback(x, args.settings_file_path))
        else:
            with open(settings_file) as file_data:
                cached_settings = json.load(file_data, object_hook=from_json)
            logger.info('Reusing settings: {0!s}'.format(settings_file))

            device_id = cached_settings.get('device_id')

            api = Client(
                args.username, args.password,
                settings=cached_settings)

    except (ClientCookieExpiredError, ClientLoginRequiredError) as e:
        logger.info('ClientCookieExpiredError/ClientLoginRequiredError: {0!s}'.format(e))

        api = Client(
            args.username, args.password,
            device_id=device_id,
            on_login=lambda x: onlogin_callback(x, args.settings_file_path))

    except ClientLoginError as e:
        logger.error('ClientLoginError {0!s}'.format(e))
        exit(9)
    except ClientError as e:
        logger.critical('ClientError {0!s} (Code: {1:d}, Response: {2!s})'.format(e.msg, e.code, e.error_response))
        exit(9)
    except Exception as e:
        logger.critical('Unexpected Exception: {0!s}'.format(e))
        exit(99)

    cookie_expiry = api.cookie_jar.auth_expires
    logger.info('Cookie Expiry: {0!s}'.format(datetime.datetime.fromtimestamp(cookie_expiry).strftime('%Y-%m-%dT%H:%M:%SZ')))

    return api

def comparePK(user):
  return user['pk']

def following(api):
    rank_token = Client.generate_uuid()
    result = api.user_following(api.authenticated_user_id, rank_token, count=1000, extract='false')
    result["users"].sort(key=comparePK)
    
    return list(( item['pk'] for item in result["users"] ))

def followers(api):
    rank_token = Client.generate_uuid()
    result = api.user_followers(api.authenticated_user_id, rank_token, count=1000, extract='false')
    
    return list(( item['pk'] for item in result["users"] ))

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(levelname)-4s %(message)s',
            level=logging.INFO,
            datefmt='%Y-%m-%d %H:%M:%S',
            filename="./unfollow.log")
    logger = logging.getLogger('unfollow')
 
    api = login()
    
    followers = followers(api)
    following = following(api)
    
    filteredPK = [i for i in following if i not in followers]
     
    for index, pk in enumerate(filteredPK):
        unfollowed = api.friendships_destroy(pk)
        if unfollowed['status'] == 'ok':
          user = api.user_info(pk)

        logger.info('Unfollowed user - ID: %s, Username: %s, Full Name: %s.', pk, user['user']['username'], user['user']['full_name'])
