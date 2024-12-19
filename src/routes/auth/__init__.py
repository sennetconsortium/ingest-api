from flask import Blueprint, redirect, request, session, current_app, Response, make_response
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient, AuthAPIError
import json
import logging
import base64

from hubmap_commons.hm_auth import AuthHelper

auth_blueprint = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Endpoints for UI Login and Logout

# Redirect users from react app login page to Globus auth login widget then redirect back
@auth_blueprint.route('/login')
def login():
    return _login(redirect_uri=current_app.config['GLOBUS_CLIENT_APP_URI'], inciting_url='/login')

@auth_blueprint.route('/data-ingest-board-login')
def data_ingest_login():
    return _login(redirect_uri=current_app.config['DATA_INGEST_BOARD_APP_URI'], key='ingest_board_tokens', inciting_url='data-ingest-board-logout')


@auth_blueprint.route('/logout')
def logout():
    return _logout(redirect_uri=current_app.config['GLOBUS_CLIENT_APP_URI'], app_name=current_app.config['GLOBUS_CLIENT_APP_NAME'])


@auth_blueprint.route('/data-ingest-board-logout')
def data_ingest_logout():
    return _logout(redirect_uri=current_app.config['DATA_INGEST_BOARD_APP_URI'], app_name=current_app.config['DATA_INGEST_BOARD_NAME'],  key='ingest_board_tokens')


def get_user_info(token):
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(token))
    return auth_client.oauth2_userinfo()


def get_auth_header_dict(token) -> dict:
    return {'Authorization': 'Bearer ' + token,  'X-SenNet-Application': 'ingest-api'}


def get_auth_header() -> dict:
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    return get_auth_header_dict(token)

def _login(redirect_uri, key = 'tokens', inciting_url = '/login'):
    #redirect_uri = url_for('login', _external=True)
    _redirect_uri = current_app.config['FLASK_APP_BASE_URI'] + request.path.replace('/', '')

    confidential_app_auth_client = \
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])
    confidential_app_auth_client.oauth2_start_flow(_redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        params = {"scope": "openid profile email urn:globus:auth:scope:transfer.api.globus.org:all urn:globus:auth:scope:auth.globus.org:view_identities urn:globus:auth:scope:groups.api.globus.org:all"}
        auth_uri = confidential_app_auth_client.oauth2_get_authorize_url(additional_params=params)
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        auth_code = request.args.get('code')

        try:
            token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)
        except AuthAPIError as e:
            logger.error(e)
            # The exchange for token for a code has failed so start the process again
            return redirect(inciting_url)

        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        #nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        groups_token = token_response.by_resource_server['groups.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)

        # Check if user has read permissions
        auth_helper_instance: AuthHelper = AuthHelper.instance()
        read_privs = auth_helper_instance.has_read_privs(groups_token)
        if isinstance(read_privs, Response):
            return read_privs


        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            'transfer_token': transfer_token,
            'read_privs': read_privs,
            'groups_token': groups_token
        }

        # Turns json dict into a str
        json_str = json.dumps(info)

        # Store the resulting tokens in server session
        # session.update(
        #     tokens=token_response.by_resource_server
        # )
        session[key] = token_response.by_resource_server

        logger.info(f"Logged in User: {user_info['name']}")

        # encode this to avoid the \\" type strings when reading cookies from the client
        b = base64.b64encode(bytes(json_str, 'utf-8'))  # bytes
        base64_json_str = b.decode('utf-8')  # convert bytes to string

        # create a response for the user
        response = make_response(redirect(redirect_uri))
        #Use max_age (seconds) as opposed to expires (date). Set token to expire after 1 day
        if current_app.config['COOKIE_DOMAIN'] == 'localhost':
            response.set_cookie('info',
                                base64_json_str,
                                max_age=86400,
                                samesite='Lax')
        else:
            print('setting domain cookie')
            response.set_cookie('info',
                                base64_json_str,
                                max_age=86400,
                                domain=current_app.config['COOKIE_DOMAIN'],
                                samesite='Lax',
                                secure=True)
        return response


def _logout(redirect_uri, app_name, key='tokens'):
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    confidential_app_auth_client = \
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])

    # Revoke the tokens with Globus Auth
    if key in session:
        for token in (token_info['access_token']
                      for token_info in session[key].values()):
            confidential_app_auth_client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
            'https://auth.globus.org/v2/web/logout' +
            '?client={}'.format(current_app.config['APP_CLIENT_ID']) +
            '&redirect_uri={}'.format(redirect_uri) +
            '&redirect_name={}'.format(app_name))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)
