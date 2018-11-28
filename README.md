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

For a demonstration project (in spanish) see https://github.com/hablutzel1/blobfish-ejbca-client-ruby-demo.

## Operation considerations

### Clock synchronization between Ruby and EJBCA side

End of validity of certificates is calculated and fixed by adding the expected lifetime of certificates (e.g. 365 days) to the current time in the Ruby side, but the start of validity of certificates is determined by the current time in the EJBCA side. Because of the previous, **it is really important to keep clocks synchronized between Ruby and EJBCA side** because synchronization problems could produce inconsistent validity periods in issued certificates.