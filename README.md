# Blobfish::Ejbca

This gem allows integration with EJBCA services and currently supports: 

- PFX generation on EJBCA side.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'blobfish-ejbca-client-ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install blobfish-ejbca-client-ruby

## Usage

For a demonstration project see https://github.com/hablutzel1/blobfish-ejbca-client-ruby-demo.

## Access rules required for client certificate

The EJBCA Role for the client certificate to be used with this gem requires the following Access Rules (TODO confirm if these access rules could be reduced further in Advanced Mode edition):

- **Role Template**: RA Administrators
- **Authorized CAs**: MyCertificationAuthority
- **End Entity Rules**: 
  - Create End Entities
  - Edit End Entities
  - Revoke End Entities
  - View End Entities
- **End Entity Profiles**: MyEndEntityProfile

Always remember that Access Rules for a client of this type should be restricted as much as possible; **credentials for a superadmin should never be used!**.
