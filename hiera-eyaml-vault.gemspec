lib = File.expand_path('lib', File.dirname(__FILE__))
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)


Gem::Specification.new do |gem|
  gem.name          = "hiera-eyaml-vault_rs"
  gem.version       = "1.2.1"
  gem.description   = "Eyaml plugin for Vault transit secrets engine.  Forked from https://github.com/crayfishx/hiera-eyaml-vault"
  gem.summary       = "Encryption plugin for hiera-eyaml to use Vault's transit secrets engine"
  gem.authors        = ["ryan-scheinberg","Craig Dunn"]
  gem.license       = "Apache-2.0"

  gem.homepage      = "https://github.com/ryan-scheinberg/hiera-eyaml-vault"
  gem.files         = Dir["lib/**/*"]
  gem.add_dependency 'hiera-eyaml', '< 4.0.0'
end
