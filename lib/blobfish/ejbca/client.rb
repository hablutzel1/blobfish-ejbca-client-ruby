require 'savon'
require 'base64'

module Blobfish
  module Ejbca

    # See too 'D:\d\ejbca\tests\ejbca_ws_client\src\p12onejbcaside' for a Java alternative for this client.
    class Client

      USERNAME_PREFIX = 'llama_'
      STATUS_NEW = 10
      TOKEN_TYPE_P12 = 'P12'

      def initialize(wsdl_url, ws_client_certificate, ws_client_key, ws_client_key_password, ca_name, cert_profile, ee_profile)
        @client = Savon.client(
            :wsdl => wsdl_url,
            :ssl_cert_file => ws_client_certificate,
            :ssl_cert_key_file => ws_client_key,
            :ssl_cert_key_password => ws_client_key_password,
        # Only for development.
        # :ssl_ca_cert_file => "C:/Users/hablu/Desktop/managementca.cer",
        # log: true,
        # log_level: :debug,
        )
        @ca_name = ca_name
        @cert_profile = cert_profile
        @ee_profile = ee_profile
      end

      def request_pfx(tax_number, company_name, nid, surname, given_name, email_address, locality, pfx_password)
        username = USERNAME_PREFIX + tax_number + "_" + nid
        @client.call(:edit_user, soap_action: false, message: {
            :arg0 => {
                :username => username,
                :password => pfx_password,
                :status => STATUS_NEW,
                :token_type => TOKEN_TYPE_P12,
                :email => email_address,
                :subjectDN => "CN=" + given_name + " " + surname + ",emailAddress=" + email_address + ",serialNumber=" + nid + ",O=" + company_name + ",OU=" + tax_number + ",L=" + locality + ",C=PE",
                :subject_alt_name => "rfc822name=" + email_address,
                :ca_name => @ca_name,
                :certificate_profile_name => @cert_profile,
                :end_entity_profile_name => @ee_profile,
            }
        })
        response = @client.call(:pkcs12_req, soap_action: false, message: {
            :arg0 => username,
            :arg1 => pfx_password,
            :arg2 => nil,
            :arg3 => "2048",
            :arg4 => "RSA"
        })
        base64_resp = response.to_hash[:pkcs12_req_response][:return][:keystore_data]
        # Note that it requires double Base64 decoding.
        base64_resp = Base64.decode64(base64_resp)
        Base64.decode64(base64_resp)
      end

    end
  end
end
