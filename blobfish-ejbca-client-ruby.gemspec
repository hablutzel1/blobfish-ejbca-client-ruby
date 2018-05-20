# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "blobfish/ejbca/version"

Gem::Specification.new do |spec|
  spec.name          = "blobfish-ejbca-client-ruby"
  spec.version       = Blobfish::Ejbca::VERSION
  spec.authors       = ["Jaime Hablutzel"]
  spec.email         = ["hablutzel1@gmail.com"]

  spec.summary       = "Blobfish's Ruby client for EJBCA services."
  spec.description   = "Ruby client currently allowing to perform certain operations with EJBCA services, e.g. requesting PFX generation."
  spec.homepage      = "https://github.com/hablutzel1/blobfish-ejbca-client-ruby"


  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]
  spec.add_runtime_dependency 'savon', '~> 2.12'
  spec.add_development_dependency "bundler", "~> 1.16"
end
