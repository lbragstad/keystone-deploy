import json
import os
import requests
import unittest

from keystoneauth1.auth.identity.v3 import k2k as k2k_plugin
from keystoneauth1.auth.identity.v3 import password as password_plugin
from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client


def bootstrap(endpoint_ip):
    c = client.Client(
        token='ADMIN',
        endpoint='http://' + endpoint_ip + ':35357/v3')

    domain = c.domains.get('default')

    roles = c.roles.list(name='admin')
    if roles:
        role = roles[0]
    else:
        role = c.roles.create(name='admin')

    groups = c.groups.list(domain=domain, name='admin')
    if groups:
        group = groups[0]
    else:
        group = c.groups.create(domain=domain, name='admin')

    c.roles.grant(group=group, domain=domain, role=role)

    projects = c.projects.list(domain=domain, name='admin')
    if projects:
        project = projects[0]
    else:
        project = c.projects.create(domain=domain, name='admin')

    c.roles.grant(group=group, project=project, role=role)

    password = 'password'
    users = c.users.list(domain=domain, name='admin')
    if users:
        user = users[0]
    else:
        user = c.users.create(
            domain=domain, name='admin', password=password)

    c.users.add_to_group(user=user, group=group)

    services = c.services.list(
        name='Keystone', type='identity')
    if services:
        service = services[0]
    else:
        service = c.services.create(
            name='Keystone', type='identity')

    endpoints = c.endpoints.list()
    if not [x for x in endpoints if x.interface == 'public']:
        c.endpoints.create(
            service=service,
            interface='public',
            url=endpoint_ip + 'v3')
    if not [x for x in endpoints if x.interface == 'admin']:
        c.endpoints.create(
            service=service,
            interface='admin',
            url=endpoint_ip + 'v3')

    return (domain.name, role.id, project.id, user.name, password)


class K2KFederationTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # collect service provider info
        cls.sp_id = os.environ.get('OS_SP_ID')
        cls.sp_ip = os.environ.get('OS_SP_IP')
        cls.sp_endpoint_url = 'https://%s/v3' % cls.sp_ip
        # collect identity provider info
        cls.idp_ip = os.environ.get('OS_IDP_IP')
        cls.idp_endpoint_url = 'https://%s/v3' % cls.idp_ip

        # bootstrap service provider
        (cls.sp_domain_name, cls.sp_role_id, cls.sp_project_id,
            cls.sp_user_name, cls.sp_user_pass) = bootstrap(cls.sp_ip)
        # bootstrap identity provider
        (cls.idp_domain_name, cls.idp_role_id, cls.idp_project_id,
            cls.idp_user_name, cls.idp_user_pass) = bootstrap(cls.idp_ip)

        # setup the service provider and the identity provider
        cls._setup_identity_provider()
        cls._setup_service_provider()

    @classmethod
    def _setup_service_provider(cls):
        a = v3.Password(auth_url=cls.sp_endpoint_url,
                        username=cls.sp_user_name,
                        password=cls.sp_user_pass,
                        user_domain_name=cls.sp_domain_name,
                        project_id=cls.sp_project_id,
                        project_domain_name=cls.sp_domain_name)
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

        c.roles.grant(role=cls.sp_role_id, group=group, domain=domain)
        c.roles.grant(role=cls.sp_role_id, group=group,
                      project=cls.sp_project_id)

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
        remote_id = cls.idp_endpoint_url + '/OS-FEDERATION/SAML2/idp'
        idp_ref = {'id': idp_id, 'remote_ids': [remote_id], 'enabled': True}
        idps = c.federation.identity_providers.list(id=idp_id)
        if idps:
            idp = idps[0]
        else:
            idp = c.federation.identity_providers.create(**idp_ref)

        protocols = c.federation.protocols.list(idp, protocol='saml2')
        if not protocols:
            c.federation.protocols.create('saml2', idp, mapping)

    @classmethod
    def _setup_identity_provider(cls):
        a = v3.Password(auth_url=cls.idp_endpoint_url,
                        username=cls.idp_user_name,
                        password=cls.idp_user_pass,
                        user_domain_name=cls.idp_domain_name,
                        project_id=cls.idp_project_id,
                        project_domain_name=cls.idp_domain_name)
        s = session.Session(auth=a, verify=False)
        c = client.Client(session=s)

        sp_url = 'https://%s/Shibboleth.sso/SAML2/ECP' % cls.sp_ip
        auth_url = ''.join(['https://%s/v3/OS-FEDERATION/identity_providers/',
                            'keystone-idp/protocols/saml2/auth']) % cls.sp_ip
        sp_ref = {
            'id': cls.sp_id,
            'sp_url': sp_url,
            'auth_url': auth_url,
            'enabled': True
        }
        service_providers = c.federation.service_providers.list(id=cls.sp_id)
        if not service_providers:
            c.federation.service_providers.create(**sp_ref)

    def assertValidProjectScopedTokenResponse(self, r):
        token = json.loads(r.text)['token']

        self.assertIn('project', token)
        self.assertIn('id', token['project'])
        self.assertIn('name', token['project'])
        self.assertIn('domain', token['project'])
        self.assertIn('id', token['project']['domain'])
        self.assertIn('name', token['project']['domain'])

    def test_full_workflow(self):
        CREDENTIALS = {
            'auth_url': self.idp_endpoint_url,
            'username': self.idp_user_name,
            'user_domain_name': self.idp_domain_name,
            'password': self.idp_user_pass,
            'project_id': self.idp_project_id
        }
        s = session.Session(verify=False)
        passwd = password_plugin.Password(**CREDENTIALS)
        K2K_CREDENTIALS = {
            'base_plugin': passwd,
            'service_provider': self.sp_id,
        }

        # get an unscoped token
        k2k = k2k_plugin.Keystone2Keystone(**K2K_CREDENTIALS)
        access = k2k.get_access(s)
        unscoped_federated_token = access.auth_token

        # get a list of projects from the service provider
        projects = requests.get(
            url=self.sp_endpoint_url + '/auth/projects',
            headers={'X-Auth-Token': unscoped_federated_token},
            verify=False)
        projects = json.loads(projects.text)
        project_id = projects.get('projects')[0]['id']

        # get a project scoped token from the service provider
        K2K_CREDENTIALS = {
            'base_plugin': passwd,
            'service_provider': self.sp_id,
            'project_id': project_id
        }
        k2k = k2k_plugin.Keystone2Keystone(**K2K_CREDENTIALS)
        access = k2k.get_access(s)
        scoped_federated_token = access.auth_token

        # validate the project scoped token
        r = requests.get(
            url=self.sp_endpoint_url + '/auth/tokens',
            headers={'X-Auth-Token': scoped_federated_token,
                     'X-Subject-Token': scoped_federated_token},
            verify=False)

        self.assertValidProjectScopedTokenResponse(r)
