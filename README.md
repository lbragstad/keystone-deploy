# Deploy keystone to keystone federation from source

This illustrates a deployment of [OpenStack
keystone](http://keystone.openstack.org/) from
[source](https://github.com/openstack/keystone), primarily geared towards
documenting and testing various configurations.

## Usage

This repository is designed to deploy keystone to keystone federation to
arbitrary hosts using ansible. You'll at least need `sudo` access on that host,
if not `root`.

Start by installing the project's dependencies:

    pip install -r requirements.txt

Copy the sample Ansible inventory file to create a custom inventory, where you
can specify your host and any custom variables:

    cp sample_inventory inventory

A sample inventory for deploying keystone-to-keystone federation might look
something like:

    [echo]
    <echo-ip>

    [service_provider]
    <service-provider-ip

    [identity_provider]
    <identity-provider-ip>

    [db:children]
    service_provider
    identity_provider

Next, install ansible dependencies:

    ansible-galaxy install --roles-path=playbooks/roles/ --role-file=ansible-requirements.txt

And then you can deploy keystone:

    ansible-playbook -i inventory deploy.yaml

Note that you might need to specify how ansible should authenticate with the
host, and how to obtain root permissions. See `ansible-playbook --help` for
the available options.

## How it works

The ansible playbooks deploy both `keystone` and a tiny service protected by
`keystonemiddleware.auth_token` called `echo`. The playbooks will deploy a
keystone identity provider as well as a keystone service provider. Ansible will
also do some orchestration between the two to build a trust necessary for
federation.

![Sequence diagram](http://www.websequencediagrams.com/cgi-bin/cdraw?lz=Q2xpZW50LT4ra2V5c3RvbmU6IEF1dGhlbnRpY2F0ZQoADwgtLT4tACYGOiBUb2tlbgoAMQlhdXRoX3Rva2VuOiBBUEkgcmVxdWVzdCArIAAQBQoAFgoAWg1WYWxpZGF0ZQAfBwBdDABFDXV0aCBjb250ZXh0AD0OZWNobyBzZXJ2aWNlAGoQYQAqDAAdDACBPAwAgScGc3BvbnNlCg&s=napkin)

## Testing


To exercise a deployment, run:

    OS_SP_ID='keystone.sp' \
    OS_SP_IP=keystone-sp.example.com \
    OS_IDP_IP=keystone-idp.example.com  python -m unittest discover

The tests will populate each keystone node with initial data. The setup of the
tests will also ensure the service provider and identity provider know about
each other.
