from flask import Blueprint, redirect, request, session, current_app
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient
import json
import logging

from hubmap_commons.hm_auth import AuthHelper

auth_blueprint = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Endpoints for UI Login and Logout

# Redirect users from react app login page to Globus auth login widget then redirect back
@auth_blueprint.route('/login')
def login():
    return _login(current_app.config['GLOBUS_CLIENT_APP_URI'])

@auth_blueprint.route('/data-ingest-board-login')
def data_ingest_login():
    return _login(redirect_uri=current_app.config['DATA_INGEST_BOARD_APP_URI'], key='ingest_board_tokens')


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

def _login(redirect_uri, key = 'tokens'):
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

        token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)

        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        #nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        groups_token = token_response.by_resource_server['groups.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)

        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            'transfer_token': transfer_token,
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
        # Finally redirect back to the client
        return redirect(redirect_uri + '?info=' + str(json_str))


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