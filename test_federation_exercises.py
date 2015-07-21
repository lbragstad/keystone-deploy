import os
import requests
import unittest

from keystoneauth1.auth.identity.v3 import k2k as k2k_plugin
from keystoneauth1.auth.identity.v3 import password as password_plugin
from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client

# Service Provider information
SP_IP = os.environ.get('OS_SP_IP')
SP_ENDPOINT = 'https://%s/v3' % SP_IP

# Identity Provider information
IDP_IP = os.environ.get('OS_IDP_IP')
IDP_ENDPOINT = 'https://%s/v3' % IDP_IP


class K2KFederationTestCase(unittest.TestCase):

    def setUp(self):
        # Setup the service provider and the identity provider
        self.sp_id = os.environ.get('OS_SP_ID')
        self.auth_url = os.environ.get('OS_AUTH_URL')
        self.project_id = os.environ.get('OS_PROJECT_ID')
        self.sp_project_id = os.environ.get('OS_SP_PROJECT_ID')
        self.username = os.environ.get('OS_USERNAME')
        self.password = os.environ.get('OS_PASSWORD')
        self.domain_id = os.environ.get('OS_DOMAIN_ID')
        self._setup_identity_provider()
        self._setup_service_provider()

    def _setup_service_provider(self):
        a = v3.Password(auth_url=SP_ENDPOINT,
                        username='admin',
                        password='password',
                        user_domain_name='Default',
                        project_name='admin',
                        project_domain_name='Default')
        s = session.Session(auth=a, verify=False)
        c = client.Client(session=s)

        domain_name = 'domain1'
        domains = c.domains.list(name=domain_name)
        if domains:
            domain = domains[0]
        else:
            domain = c.domains.create(name=domain_name)

        group_name = 'group1'
        groups = c.groups.list(domain=domain, name=group_name)
        if groups:
            group = groups[0]
        else:
            group = c.groups.create(domain=domain, name=group_name)

        role_name = 'admin'
        roles = c.roles.list(name='admin')
        if roles:
            role = roles[0]
        else:
            role = c.roles.create(name=role_name)

        c.roles.grant(role=role, group=group, domain=domain)
        c.roles.grant(role=role, group=group, project=self.sp_project_id)

        rules = [{
            "local": [
                {
                    "user": {
                        "name": "federated_user"
                    },
                    "group": {
                        "id": group.id
                    }
                }
            ],
            "remote": [
                {
                    "type": "openstack_user",
                    "any_one_of": [
                        "user1",
                        "admin"
                    ]
                }
            ]
        }
        ]
        mapping_id = 'keystone-idp-mapping'
        mappings = c.federation.mappings.list(id=mapping_id)
        if mappings:
            mapping = mappings[0]
        else:
            mapping = c.federation.mappings.create(mapping_id=mapping_id,
                                                   rules=rules)

        idp_id = 'keystone-idp'
        remote_id = IDP_ENDPOINT + '/OS-FEDERATION/SAML2/idp'
        idp_ref = {'id': idp_id, 'remote_ids': [remote_id], 'enabled': True}
        idps = c.federation.identity_providers.list(id=idp_id)
        if idps:
            idp = idps[0]
        else:
            idp = c.federation.identity_providers.create(**idp_ref)

        protocols = c.federation.protocols.list(idp, protocol='saml2')
        if not protocols:
            c.federation.protocols.create('saml2', idp, mapping)

    def _setup_identity_provider(self):
        a = v3.Password(auth_url=IDP_ENDPOINT,
                        username='admin',
                        password='password',
                        user_domain_name='Default',
                        project_name='admin',
                        project_domain_name='Default')
        s = session.Session(auth=a, verify=False)
        c = client.Client(session=s)

        sp_id = 'keystone.sp'
        sp_url = 'https://%s/Shibboleth.sso/SAML2/ECP' % SP_IP
        auth_url = ''.join(['https://%s/v3/OS-FEDERATION/identity_providers/',
                            'keystone-idp/protocols/saml2/auth']) % SP_IP
        sp_ref = {
            'id': sp_id,
            'sp_url': sp_url,
            'auth_url': auth_url,
            'enabled': True
        }
        service_providers = c.federation.service_providers.list(id=sp_id)
        if not service_providers:
            c.federation.service_providers.create(**sp_ref)

    def test_full_workflow(self):
        CREDENTIALS = {
            'auth_url': 'https://104.239.165.190/v3',
            'username': 'admin',
            'user_domain_name': 'default',
            'password': 'password',
            # project_id of the identity provider
            'project_id': '92a0b22275284c83b3efc37433751038'

        }

        s = session.Session(verify=False)
        passwd = password_plugin.Password(**CREDENTIALS)
        K2K_CREDENTIALS = {
            'base_plugin': passwd,
            'service_provider': 'keystone.sp',
        }

        k2k = k2k_plugin.Keystone2Keystone(**K2K_CREDENTIALS)
        access = k2k.get_access(s)

        fed_token = access.auth_token

        requests.get(
            url='https://104.239.165.207/v3/auth/projects',
            headers={'X-Auth-Token': fed_token},
            verify=False)
