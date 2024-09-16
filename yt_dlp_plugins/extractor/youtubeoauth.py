import datetime
import json
import time
import urllib.parse
import uuid
import os

import yt_dlp.networking
from yt_dlp.utils import ExtractorError
from yt_dlp.utils.traversal import traverse_obj
from yt_dlp.extractor.common import InfoExtractor
from yt_dlp.extractor.youtube import YoutubeBaseInfoExtractor
import importlib
import inspect

import sqlite3
import json
import datetime


_EXCLUDED_IES = ('YoutubeBaseInfoExtractor', 'YoutubeTabBaseInfoExtractor')

YOUTUBE_IES = filter(
    lambda member: issubclass(member[1], YoutubeBaseInfoExtractor) and member[0] not in _EXCLUDED_IES,
    inspect.getmembers(importlib.import_module('yt_dlp.extractor.youtube'), inspect.isclass)
)

__VERSION__ = '2024.09.14'

_CLIENT_ID = '861556708454-d6dlm3lh05idd8npek18k6be8ba3oc68.apps.googleusercontent.com'
_CLIENT_SECRET = 'SboVhoG9s0rNafixCSGGKXAT'
_SCOPES = 'http://gdata.youtube.com https://www.googleapis.com/auth/youtube'

class TokenManager:
    def __init__(self, db_file='config.db'):
        self.db_file = db_file
        self.create_table()

    def create_table(self):
        """Create the token table if it does not exist."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS token (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_token TEXT NOT NULL,
                expires INTEGER NOT NULL,
                refresh_token TEXT NOT NULL,
                token_type TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def store_token(self, token_data):
        """Store or update token data in the database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO token (access_token, expires, refresh_token, token_type)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
            access_token=excluded.access_token,
            expires=excluded.expires,
            refresh_token=excluded.refresh_token,
            token_type=excluded.token_type
        ''', (token_data['access_token'], token_data['expires'], token_data['refresh_token'], token_data['token_type']))
        
        conn.commit()
        conn.close()

    def get_token(self):
        """Retrieve the most recent token data from the database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT access_token, expires, refresh_token, token_type FROM token ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            return {
                'access_token': row[0],
                'expires': row[1],
                'refresh_token': row[2],
                'token_type': row[3]
            }
        return None
 
    '''token_manager.store_token(token_data)
    
    token = token_manager.get_token()'''


class YouTubeOAuth2Handler(InfoExtractor):

    def set_downloader(self, downloader):
        super().set_downloader(downloader)
        if downloader:
            downloader.write_debug(f'YouTube OAuth2 plugin version {__VERSION__}', only_once=True)

    def store_token(self, token_data):
        self._TOKEN_DATA = token_data
        os.environ["AUTH_TOKEN"] = json.dumps(token_data)

    def get_token(self):
        token_data = self._TOKEN_DATA
        if not token_data:
            token_data = os.environ.get("AUTH_TOKEN")
            if token_data:
                self._TOKEN_DATA = json.loads(token_data)
        return self._TOKEN_DATA

    def validate_token_data(self, token_data):
        return all(key in token_data for key in ('access_token', 'expires', 'refresh_token', 'token_type'))

    def initialize_oauth(self):
        token_data = self.get_token()

        if token_data and not self.validate_token_data(token_data):
            self.report_warning('Invalid cached OAuth2 token data')
            token_data = None

        if not token_data:
            token_data = self.authorize()
            self.store_token(token_data)

        if token_data['expires'] < datetime.datetime.now(datetime.timezone.utc).timestamp() + 60:
            self.to_screen('Access token expired, refreshing')
            token_data = self.refresh_token(token_data['refresh_token'])
            self.store_token(token_data)

        return token_data

    def handle_oauth(self, request: yt_dlp.networking.Request):

        if not urllib.parse.urlparse(request.url).netloc.endswith('youtube.com'):
            return

        token_data = self.initialize_oauth()
        request.headers.pop('X-Goog-PageId', None)
        request.headers.pop('X-Goog-AuthUser', None)
        if 'Authorization' in request.headers:
            self.report_warning(
                'Youtube cookies have been provided, but OAuth2 is being used.'
                ' If you encounter problems, stop providing Youtube cookies to yt-dlp.')
            request.headers.pop('Authorization', None)
            request.headers.pop('X-Origin', None)
        request.headers.pop('X-Youtube-Identity-Token', None)

        authorization_header = {'Authorization': f'{token_data["token_type"]} {token_data["access_token"]}'}
        request.headers.update(authorization_header)

    def refresh_token(self, refresh_token):
        token_response = self._download_json(
            'https://www.youtube.com/o/oauth2/token',
            video_id='oauth2',
            note='Refreshing OAuth2 Token',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'client_secret': _CLIENT_SECRET,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})
        error = traverse_obj(token_response, 'error')
        if error:
            self.report_warning(f'Failed to refresh access token: {error}. Restarting authorization flow')
            return self.authorize()

        return {
            'access_token': token_response['access_token'],
            'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
            'token_type': token_response['token_type'],
            'refresh_token': token_response.get('refresh_token', refresh_token)
        }

    def authorize(self):
        code_response = self._download_json(
            'https://www.youtube.com/o/oauth2/device/code',
            video_id='oauth2',
            note='Initializing OAuth2 Authorization Flow',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'scope': _SCOPES,
                'device_id': uuid.uuid4().hex,
                'device_model': 'ytlr::'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

        verification_url = code_response['verification_url']
        user_code = code_response['user_code']
        self.to_screen(f'To give yt-dlp access to your account, go to {verification_url} and enter code {user_code}')

        while True:
            token_response = self._download_json(
                'https://www.youtube.com/o/oauth2/token',
                video_id='oauth2',
                note=False,
                data=json.dumps({
                    'client_id': _CLIENT_ID,
                    'client_secret': _CLIENT_SECRET,
                    'code': code_response['device_code'],
                    'grant_type': 'http://oauth.net/grant_type/device/1.0'
                }).encode(),
                headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

            error = traverse_obj(token_response, 'error')
            if error:
                if error == 'authorization_pending':
                    time.sleep(code_response['interval'])
                    continue
                elif error == 'expired_token':
                    self.report_warning('The device code has expired, restarting authorization flow')
                    return self.authorize()
                else:
                    raise ExtractorError(f'Unhandled OAuth2 Error: {error}')

            self.to_screen('Authorization successful')
            return {
                'access_token': token_response['access_token'],
                'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
                'refresh_token': token_response['refresh_token'],
                'token_type': token_response['token_type']
            }


for _, ie in YOUTUBE_IES:
    class _YouTubeOAuth(ie, YouTubeOAuth2Handler, plugin_name='oauth2'):
        _NETRC_MACHINE = 'youtube'
        _use_oauth2 = False

        _OAUTH2_UNSUPPORTED_CLIENTS = ('web_creator', 'android_creator', 'ios_creator')
        _OAUTH2_CLIENTS = ('mweb', )

        def _perform_login(self, username, password):
            if username == 'oauth2':
                self._use_oauth2 = True
                self.initialize_oauth()
                self._DEFAULT_CLIENTS = tuple(
                    c for c in getattr(self, '_DEFAULT_CLIENTS', []) if c not in self._OAUTH2_UNSUPPORTED_CLIENTS
                ) + self._OAUTH2_CLIENTS
                return

            return super()._perform_login(username, password)

        def _create_request(self, *args, **kwargs):
            request = super()._create_request(*args, **kwargs)
            if '__youtube_oauth__' in request.headers:
                request.headers.pop('__youtube_oauth__')
            elif self._use_oauth2:
                self.handle_oauth(request)
            return request

        @property
        def is_authenticated(self):
            if self._use_oauth2:
                token_data = self.get_token()
                return token_data and self.validate_token_data(token_data)
            return super().is_authenticated
