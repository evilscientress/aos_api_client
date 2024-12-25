from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import Optional, Mapping


class APCertType(StrEnum):
    FACTORY = 'factory-cert'
    SWITCH = 'switch-cert'


class CPSecAPState(StrEnum):
    CERTIFIED_FACTORY = 'certified-factory-cert'
    APPROVED_READY_FOR_CERT = 'approved-ready-for-cert'


@dataclass
class CPSecAllowlistEntry():
    mac_address: str
    ap_group: Optional[str]
    ap_name: Optional[str]
    enable: Optional[bool]
    state: Optional[CPSecAPState]
    cert_type: Optional[APCertType]
    description: Optional[str]
    revoke_text: Optional[str]
    last_updated: Optional[datetime]


    @classmethod
    def from_api_data(cls, data: Mapping):
        last_updated = datetime.strptime(data.get('Last Updated'), '%a %b %d %H:%M:%S %Y')
        cert_type = APCertType(data.get('Cert-Type'))
        state = CPSecAPState(data.get('State'))
        return cls(
            mac_address=data.get('MAC-Address'),
            ap_group=data.get('AP-Group'),
            ap_name=data.get('AP-Name'),
            enable=True if data.get('Enable').lower() == 'enabled' else False,
            state=state,
            cert_type=cert_type,
            description=data.get('Description'),
            revoke_text=data.get('Revoke Text'),
            last_updated=last_updated,
        )