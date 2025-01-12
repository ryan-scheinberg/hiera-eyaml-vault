# Hiera-Eyaml-Vault #

## Introduction ##

This library is a plugin to [hiera-eyaml](https://github.com/voxpupuli/hiera-eyaml) that enabled encryption and decryption using the [Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit/index.html) of [Vault](https://vaultproject.io).

## Installation ##

Follow the instructions provided to install and configure hiera-eyaml, this extension can be installed as a rubygem

```
$ gem install hiera-eyaml-vault
```

## Configuration

### Vault setup

In order to use Vault as a _encryption as a service_ with this plugin you need to configure the service on the Vault server in order to enable the transit engine and provide hiera-eyaml-vault with credentials to use to authenticate against the vault service.  The following steps should be run on your Vault server.

#### Enable the transit engine

```
$ vault secrets enable transit
```

#### Create a key for Hiera to encrypt and decrypt data

```
$ vault write -f transit/keys/hiera
```

#### Create a policy for Hiera

Edit a file called hiera_policy.hcl with the following contents

```
path "transit/*" {
  capabilities = [ "read", "list", "create", "update", "delete" ]
}
```

Next, add the policy with the following command

```
$ vault policy write hiera hiera_policy.hcl
```

#### Option 1: Create an Approle to use the Hiera policy

Enable the approle auth method

```
$ vault auth enable approle
```

Create the approle

```
$ vault write auth/approle/role/hiera token_ttl=10m policies=hiera
```

#### Copy the credentials

Hiera-eyaml-vault approle requires the *role_id* and *secret_id* to be configured, obtain these by issuing the following commands

```
$ vault read auth/approle/role/hiera/role-id
$ vault write -f auth/approle/role/hiera/secret-id
```

#### Option 2: Create a Cert Auth to use the Hiera policy

Enable the cert auth method

```
$ vault auth enable cert
```

Create the approle

```
$ $ vault write auth/cert/certs/puppet_servers display_name=puppet_servers policies=hiera certificate=@path_to_public_certificate.pem ttl=3600

```

## Configuring hiera-eyaml-vault

### Options

See the documentation for [Hiera-Eyaml](https://github.com/voxpupuli/hiera-eyaml) for integrating Hiera with Eyaml, and how to enable encrypting plugins.  The following options are configurable for this plugin;

* `vault_addr`: URL of the Vault server to connect to (default https://127.0.0.1:8200)
* `role_id`: App Role ID to use to authenticate (see above)
* `secret_id`: App Secret ID to use to authenticate (see above)
* `use_ssl`: Boolean, Whether to use SSL to connect to vault (default true)
* `ssl_verify`: Boolean, Whether to verify SSL certs when connecting to vault (default true)
* `transitname`: Name of the vault transit engine to use (default: transit)
* `keyname`: Name of the vault transit key to use (see above).  (default: hiera)
* `api_version`: Version of the vault API to use (default: 1)

The following options are added for the plugin to support certificate-based authentication:

* `client_cert`: Path to the client certificate for certificate-based authentication.
* `client_key`: Path to the client private key for certificate-based authentication.
* `auth_name`: Name used for certificate-based authentication. This should match the name given when adding the certificate to Vault (puppet_servers).

### App Auth Example

```
cat ~/.eyaml/config.yaml

---
encrypt_method: vault
vault_addr: https://vault.corp.com:8200
vault_role_id: 987ad87-77dd-339a-787b-798793872a
vault_secret_id: 66255f7-225c-112a-b565-99873626f3
vault_ssl_verify: false
```

### Cert Auth Example

```
cat ~/.eyaml/config.yaml

---
encrypt_method: vault
vault_addr: https://vault.corp.com:8200
client_cert: /path/to/client_cert.pem
client_key: /path/to/client_key.pem
auth_name: puppet_servers
```

### Usage

Once configured the plugin can be used as normal with hiera-eyaml, the tagname `VAULT` will be used to identify vault encrypted strings, eg:

```
$ eyaml encrypt -s foobar
string: ENC[VAULT,dmF1bHQ6djE6WlNqb3BzZUZhZ044b3NnT3hwRG9Jb1JzYVFwbHVkRVo3QTZreDlCMmRyMEI3dz09]

OR

block: >
    ENC[VAULT,dmF1bHQ6djE6WlNqb3BzZUZhZ044b3NnT3hwRG9Jb1JzYVFwbHVkRVo3QTZr
    eDlCMmRyMEI3dz09]
```

## Maintainer

Written by Craig Dunn <craig@craigdunn.org>

With thanks to [Sixt](https://sixt.de) 




