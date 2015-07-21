import json
import os
import unittest

from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client

# Service Provider information
SP_IP = os.environ.get('OS_SP_IP')
SP_CERT = os.environ.get('OS_SP_CERT')
SP_KEY = os.environ.get('OS_SP_KEY')
SP_ENDPOINT = 'https://%s/v3' % SP_IP

# Identity Provider information
IDP_IP = os.environ.get('OS_IDP_IP')
IDP_CERT = os.environ.get('OS_IDP_CERT')
IDP_KEY = os.environ.get('OS_IDP_KEY')
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
        s = session.Session(auth=a, verify=SP_CERT, cert=(SP_CERT, SP_KEY))
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
        s = session.Session(auth=a, verify=IDP_CERT, cert=(IDP_CERT, IDP_KEY))
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

    def _v3_authenticate(self):
        self.session = session.Session(
            auth=v3.Password(auth_url=self.auth_url,
                             username=self.username,
                             password=self.password,
                             user_domain_id=self.domain_id,
                             project_id=self.project_id),
            verify=False)
        self.session.auth.get_auth_ref(self.session)
        return self.session.auth.get_token(self.session)

    def _check_response(self, response):
        if not response.ok:
            raise Exception("Something went wrong, %s" % response.__dict__)

    def _get_saml2_ecp_assertion(self, token_id):
        request_body = json.dumps({
            "auth": {
                "identity": {
                    "methods": [
                        "token"
                    ],
                    "token": {
                        "id": token_id
                    }
                },
                "scope": {
                    "service_provider": {
                        "id": self.sp_id
                    }
                }
            }
        })
        url = self.auth_url + '/auth/OS-FEDERATION/saml2/ecp'
        r = self.session.post(url=url, data=request_body, verify=False)
        self._check_response(r)
        return str(r.text)

    def _get_service_provider(self):
        url = self.auth_url + '/OS-FEDERATION/service_providers/' + self.sp_id
        r = self.session.get(url=url, verify=False)
        self._check_response(r)
        sp = json.loads(r.text)[u'service_provider']
        return sp

    def _handle_http_302_ecp_redirect(self, response, location, **kwargs):
        return self.session.get(location, authenticated=False, **kwargs)

    def _exchange_assertion(self, assertion):
        """Send assertion to a Keystone SP and get token."""
        sp = self._get_service_provider()

        r = self.session.post(
            sp[u'sp_url'],
            headers={'Content-Type': 'application/vnd.paos+xml'},
            data=assertion,
            authenticated=False,
            redirect=False)

        self._check_response(r)

        r = self._handle_http_302_ecp_redirect(r, sp[u'auth_url'],
                                               headers={'Content-Type':
                                               'application/vnd.paos+xml'})
        return r

    def test_workflow(self):
        token_id = self._v3_authenticate()
        assertion = self._get_saml2_ecp_assertion(token_id)
        fed_token_response = self._exchange_assertion(assertion)
        fed_token_id = fed_token_response.headers.get('X-Subject-Token')

        r = self.session.get(
            url='https://%s/v3/OS-FEDERATION/projects' % SP_IP,
            headers={'X-Auth-Token': fed_token_id},
            verify=False)
        self._check_response(r)
        projects = json.loads(str(r.text))

        token_data = {
            "auth": {
                "identity": {
                    "methods": [
                        "token"
                    ],
                    "token": {
                        "id": fed_token_id
                    }
                },
                "scope": {
                    "project": {
                        "id": project_id
                    }
                }
            }
        }

        # project_id can be select from the list in the previous step
        token = json.dumps(token_data)
        url = 'https://%s/v3/auth/tokens' % SP_IP
        headers = {'X-Auth-Token': fed_token_id,
                   'Content-Type': 'application/json'}
        r = self.session.post(url=url, headers=headers, data=token,
                              verify=False)
        self._check_response(r)
        self.scoped_token_id = r.headers['X-Subject-Token']
        self.scoped_token = str(r.text)
