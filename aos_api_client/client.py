from pprint import pprint
from typing import Optional, Mapping

import requests

from .models.ap import APCertType, CPSecAllowlistEntry, CPSecAPState


class APIClient(object):

    base_url: str
    verify_ssl: bool
    _session: requests.Session
    _access_token: str = ''
    _csrf_token: str = ''

    def __init__(self, base_url, username: Optional[str] = None, password: Optional[str] = None, verify_ssl=False):
        self.base_url = base_url
        self._session = requests.Session()
        self._session.verify = self.verify_ssl = verify_ssl

        if username and password:
            self.login(username, password)

    def get_url(self, path: str) -> str:
        return self.base_url + path

    def _request(self, method, path, params: Optional[Mapping] = None, data: Optional[Mapping] = None,
                 json: Optional[object] = None, headers: Optional[Mapping] = None,
                 **kwargs) -> requests.Response or object:
        params = dict() if params is None else dict(params)
        headers = dict() if headers is None else dict(headers)
        if self._access_token:
            params.setdefault('UIDARUBA', self._access_token)
        if self._csrf_token:
            headers.setdefault('X-CSRF-Token', self._csrf_token)
        headers.setdefault('Accept', 'application/json')

        from pprint import pprint
        pprint(json)

        resp = self._session.request(method, self.get_url(path), params=params, data=data, json=json, headers=headers,
                                    **kwargs)
        resp.raise_for_status()

        if resp.headers.get('Content-Type', '') == 'application/json':
            json = resp.json()
            if '_global_result' in json:
                if 'UIDARUBA' in json['_global_result']:
                    self._access_token = json['_global_result']['UIDARUBA']
                if 'X-CSRF-Token' in json['_global_result']:
                    self._csrf_token = json['_global_result']['X-CSRF-Token']

            return json

        return resp

    def login(self, username: str, password: str):
        resp = self._request('POST', '/v1/api/login', data={'username': username, 'password': password})
        try:
            if resp['_global_result']['status'] == '0':
                return True
        except KeyError:
            return False  # ToDo raise API exception

    def logout(self):
        resp = self._request('POST', '/v1/api/logout')
        try:
            if resp['_global_result']['status'] == '0':
                return True
        except KeyError:
            return False  # ToDo raise API exception


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()


    def showcommand(self, command: str):
        resp = self._request('GET', '/v1/configuration/showcommand', params={'command': command})
        return resp


    def GetCPSecAllowlist(self):
        resp = self.showcommand('show whitelist-db cpsec')
        allowlist = list()
        for entry in resp['Control-Plane Security Allowlist-entry Details']:
            allowlist.append(CPSecAllowlistEntry.from_api_data(entry))
        return allowlist

    def AddCPSecAllowlistEntry(self, mac_address_or_allowlist_entry: str | CPSecAllowlistEntry, ap_name: str = None,
                               ap_group: str = None, description: str = None):
        if isinstance(mac_address_or_allowlist_entry, CPSecAllowlistEntry):
            mac_address = mac_address_or_allowlist_entry.mac_address
            ap_name = mac_address_or_allowlist_entry.ap_name
            ap_group = mac_address_or_allowlist_entry.ap_group
            description = mac_address_or_allowlist_entry.description
        else:
            mac_address = mac_address_or_allowlist_entry

        data = {
            'name': mac_address,
            'ap_name': ap_name,
            'ap_group': ap_group,
            'description': description,
        }

        for key in list(data.keys()):
            if data[key] is None:
                del data[key]

        resp = self._request('POST', '/v1/configuration/object/wdb_cpsec_add_mac', json=data)
        return resp

    def DeleteCPSecAllowlistEntry(self, mac_address_or_allowlist_entry: str | CPSecAllowlistEntry):
        if isinstance(mac_address_or_allowlist_entry, CPSecAllowlistEntry):
            mac_address = mac_address_or_allowlist_entry.mac_address
        else:
            mac_address = mac_address_or_allowlist_entry

        resp = self._request('POST', '/v1/configuration/object/wdb_cpsec_add_mac', json={
            'name': mac_address
        })
        return resp

    def ModifyCPSecAllowlistEntry(self, mac_address_or_allowlist_entry: str | CPSecAllowlistEntry,
                                  ap_name: Optional[str] = None, ap_group: Optional[str] = None,
                                  description: Optional[str] = None, enabled: Optional[bool] = None,
                                  revoke_text: Optional[str] = None, state: Optional[CPSecAPState] = None,
                                  certy_type: Optional[APCertType] = None):
        if isinstance(mac_address_or_allowlist_entry, CPSecAllowlistEntry):
            mac_address = mac_address_or_allowlist_entry.mac_address
            ap_name = mac_address_or_allowlist_entry.ap_name
            ap_group = mac_address_or_allowlist_entry.ap_group
            description = mac_address_or_allowlist_entry.description
            enabled = mac_address_or_allowlist_entry.enabled
            revoke_text = mac_address_or_allowlist_entry.revoke_text
            state = mac_address_or_allowlist_entry.state
            certy_type = mac_address_or_allowlist_entry.certy_type
        else:
            mac_address = mac_address_or_allowlist_entry

        data = {
            'name': mac_address,
            'ap_name': ap_name,
            'ap_group': ap_group,
            'description': description,
            'revoke-test': revoke_text,
        }
        for key in list(data.keys()):
            if data[key] is None:
                del data[key]

        if enabled is not None:
            data['mode'] = True
            data['modeact'] = 'enable' if enabled else 'disable'

        if certy_type is not None:
            data['cert-type'] = True
            data['certtype'] = certy_type

        if state is not None:
            data['state'] = True
            data['act'] = state

        pprint(data)

        resp = self._request('POST', '/v1/configuration/object/wdb_cpsec_modify_mac', json=data)
        return resp