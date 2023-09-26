require 'base64'
require 'hiera/backend/eyaml/encryptor'
require 'hiera/backend/eyaml/encryptors/vault/httphandler'
require 'hiera/backend/eyaml/utils'
require 'hiera/backend/eyaml/plugins'
require 'hiera/backend/eyaml/options'

class Hiera
  module Backend
    module Eyaml
      module Encryptors
        class Vault < Encryptor
          class AuthenticationError < Exception
          end
          
          HTTP_HANDLER = Hiera::Backend::Eyaml::Encryptors::Vault::Httphandler

          self.tag = 'VAULT'

          self.options = {
            :addr => {
              desc: "Address of the vault server",
              type: :string,
              default: "https://127.0.0.1:8200"
            },

            :role_id => {
              desc: "role_id for the Approle",
              type: :string,
            },

            :secret_id => {
              desc: "secret_id for the Approle",
              type: :string,
            },

            :auth_name => {
              desc: "Name for certificate-based authentication",
              type: :string,
            },

            :client_cert => {
              desc: "Path to the client certificate for certificate-based authentication",
              type: :string,
            },

            :client_key => {
              desc: "Path to the client private key for certificate-based authentication",
              type: :string,
            },

            :use_ssl => {
              desc: "Use SSL to connect to vault",
              type: :boolean,
              default: true
            },

            :ssl_verify => {
              desc: "Verify SSL certs",
              type: :boolean,
              default: true
            },

            :ssl_cert => {
              desc: "SSL Certificate to connect with",
              type: :string
            },

            :ssl_key => {
              desc: "SSL Private key to connect with",
              type: :string
            },

            :transit_name => {
              desc: "Vault transit engine name (default 'transit')",
              type: :string,
              default: "transit"
            },

            :key_name => {
              desc: "Vault transit key name (default 'hiera')",
              type: :string,
              default: "hiera"
            },

            :api_version => {
              desc: "API version to use",
              type: :integer,
              default: 1
            }
          }
          class << self

            def config_file
              ENV['EYAML_CONFIG'] || File.join(ENV['HOME'], '.eyaml/config.yaml') || '/etc/eyaml/config.yaml'
            end

            def load_config
              if File.exists?(config_file)
                @config_defaults = YAML.load_file(config_file)
              end
            end

            # Allow the inherited options method to allow for local
            # configuration to fall back on
            #
            def option(key)
              # Debug flag
              debug = ENV['EYAML_DEBUG'] == 'true'
              puts "Resolving option for key: #{key}" if debug
              
              # Load the configuration file if not already loaded
              load_config if @config_defaults.nil?
              
              # Try to resolve the option from the configuration file first
              unless @config_defaults.nil?
                config_option = @config_defaults[key.to_s]
                if config_option
                  puts "Resolved from config_defaults: #{config_option}" if debug
                  return config_option
                end
              end
              
              # Fall back to super if the configuration file doesn’t have the value
              resolved_option = super(key)
              if resolved_option
                puts "Resolved from super: #{resolved_option}" if debug
                return resolved_option
              end
              
              # If super also fails to provide a value, use the default value if available
              if self.class.options && self.class.options[key.to_sym] && self.class.options[key.to_sym][:default]
                default_value = self.class.options[key.to_sym][:default]
                puts "Using default value: #{default_value}" if debug
                return default_value
              end
              
              # If no value is found, fallback to super one more time
              puts "Falling back to super for key: #{key}" if debug
              super
            end
            

            def create_keys
              diagnostic_message = self.option :diagnostic_message 
              puts "Create_keys: #{diagnostic_message}"
            end

            def vault_url(endpoint)
              uri = []
              uri << option(:addr)
              uri << "v#{option :api_version}"
              uri << endpoint
              uri.flatten.join("/")
            end

            def login
              if option(:role_id)
                role_id = option :role_id
                secret_id = option :secret_id

                login_data = { "role_id" => role_id }
                login_data['secret_id'] = secret_id unless secret_id.nil?

                response = vault_post(login_data, :login, false)
                @login_token = response['auth']['client_token']
              elsif option(:client_cert)
                auth_name = option :auth_name

                login_data = { "name" => auth_name }

                response = vault_post(login_data, :cert_login, false)
                @login_token = response['auth']['client_token']
              end
            end

            def ssl?
              option :use_ssl
            end

            def read_file(file)
              raise Exception, "Cannot read #{file}" unless File.exists?(file)
              File.read(file)
            end

            def ssl_key
              return nil if option(:ssl_key).nil?
              @vault_ssl_key ||= read_file(option :ssl_key)
              @vault_ssl_key
            end

            def ssl_cert
              return nil if option(:ssl_cert).nil?
              @vault_ssl_cert ||= read_file(option :ssl_cert)
              @vault_ssl_cert
            end

            def client_cert
              return nil if option(:client_cert).nil?
              @vault_client_cert ||= read_file(option :client_cert)
              @vault_client_cert
            end

            def client_key
              return nil if option(:client_key).nil?
              @vault_client_key ||= read_file(option :client_key)
              @vault_client_key
            end

            def token_configured?
              return true if ENV['VAULT_TOKEN']
              not option(:token).nil?
            end

            def token
              authenticate
              ENV['VAULT_TOKEN'] || option(:token) || @login_token
            end

            def authenticate
              unless token_configured?
                login if @login_token.nil?
              end
            end

            def endpoint(action)
              # Check for the existence of a DEBUG environment variable
              debug = ENV['EYAML_DEBUG'] == 'true'

              # Compute the endpoints
              endpoints = {
                :decrypt    => "#{option(:transit_name)}/decrypt/#{option(:key_name)}",
                :encrypt    => "#{option(:transit_name)}/encrypt/#{option(:key_name)}",
                :login      => "auth/approle/login",
                :cert_login => "auth/cert/login"
              }

              # Output debug information if the debug mode is enabled
              if debug
                puts "Decrypt Endpoint: #{endpoints[:decrypt]}"
                puts "Encrypt Endpoint: #{endpoints[:encrypt]}"
              end

              endpoints[action]
            end

            def url_path(action)
              vault_url(endpoint(action))
            end

            def parse_response(response)
              body = JSON.load(response.body)
              if response.code_type == Net::HTTPOK
                return body
              else
                if response.code == "403"
                  raise AuthenticationError, body
                end
                if body['errors'].is_a?(Array)
                  message = body['errors'].join("\n")
                else
                  message = "Failed to decrypt entry #{body}"
                end
                raise Exception, "Error decrypting data from Vault: #{message}"
              end
            end

            def vault_post(data, action, use_token=true, headers={})
              url = url_path(action)
              http_options = {}
              if option(:client_cert)
                http_options = {
                  :cert   => client_cert,
                  :key    => client_key,
                }
              elsif ssl?
                http_options = {
                  :ssl        => true,
                  :ssl_verify => option(:ssl_verify),
                  :ssl_cert   => ssl_cert,
                  :ssl_key    => ssl_key,
                }
              end

              begin
                tries ||= 0
                headers['X-Vault-Token'] = token if use_token
                parse_response HTTP_HANDLER.post(url, data, headers, http_options)
              rescue AuthenticationError => e
                login
                retry if (tries += 1) < 2
                raise
              rescue HTTPError => e
                raise Exception, "HTTP Error: #{e}"
              end
            end

            def decrypt(string)
              response = vault_post({ 'ciphertext' => string}, :decrypt)
              response_data=response['data']
              Base64.decode64(response_data['plaintext'])
            end

            def encrypt(plain)
              encoded = Base64.encode64(plain)
              response = vault_post({ 'plaintext' => encoded}, :encrypt)
              response_data=response['data']
              response_data['ciphertext']
            end
          end 
        end
      end
    end
  end
end
