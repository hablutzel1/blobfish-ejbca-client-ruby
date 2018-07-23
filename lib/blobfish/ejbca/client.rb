
require 'savon'
require 'base64'
require_relative 'certificate'

module Blobfish
  module Ejbca

    # See too 'D:\d\ejbca\tests\ejbca_ws_client\src\p12onejbcaside' for a Java alternative for this client.
    class Client
      STATUS_NEW = 10
      TOKEN_TYPE_P12 = 'P12'
      REVOCATION_REASON_UNSPECIFIED = 0

      # @param [String] ws_additional_trusted_anchors e.g. +ca-certificates.crt+. Required only if +wsdl_url+ uses a non-commercial SSL certificate, otherwise it should be +nil+.
      def initialize(wsdl_url, ws_additional_trusted_anchors, ws_client_certificate, ws_client_key, ws_client_key_password, ca_name, cert_profile, ee_profile)
        @client = Savon.client(
            wsdl: wsdl_url,
            ssl_cert_file: ws_client_certificate,
            ssl_cert_key_file: ws_client_key,
            ssl_cert_key_password: ws_client_key_password,
            ssl_ca_cert_file: ws_additional_trusted_anchors,
        # log: true,
        # log_level: :debug,
        )
        @ca_name = ca_name
        @ca_dn = query_ca_dn(ca_name)
        @cert_profile = cert_profile
        @ee_profile = ee_profile
      end

      # Note that it requires 'Allow validity override' set in the EJBCA certificate profile for +validity_days+ to be effective.
      def request_pfx(ejbca_username, email_address, subject_dn, subject_alt_name, validity_days, pfx_password)
        # TODO allow to request a certificate with an explicit end date to allow for reissue capability from the RA.
        ws_call(:edit_user,
                arg0: {
                    username: ejbca_username,
                    password: pfx_password,
                    status: STATUS_NEW,
                    token_type: TOKEN_TYPE_P12,
                    email: email_address,
                    subjectDN: subject_dn,
                    subject_alt_name: subject_alt_name,
                    ca_name: @ca_name,
                    certificate_profile_name: @cert_profile,
                    end_entity_profile_name: @ee_profile,
                    extended_information: [{ name: 'customdata_ENDTIME', value: "#{validity_days}:0:0" }]
                }
        )
        ws_resp = ws_call(:pkcs12_req,
                          arg0: ejbca_username,
                          arg1: pfx_password,
                          arg2: nil,
                          arg3: '2048',
                          arg4: 'RSA'
        )
        pfx_bytes = Client.double_decode64(ws_resp[:keystore_data])
        pkcs12 = OpenSSL::PKCS12.new(pfx_bytes, pfx_password)
        {pfx: pfx_bytes, cert: Certificate.new(pkcs12.certificate)}
      end

      def revoke_cert(serial_number)
        ws_call(:revoke_cert,
                arg0: @ca_dn,
                arg1: serial_number,
                arg2: REVOCATION_REASON_UNSPECIFIED
        )
      end

      def get_revocation_status(serial_number)
        revocation_status = ws_call(:check_revokation_status,
                                    arg0: @ca_dn,
                                    arg1: serial_number,
        )
        raise "Certificate with serial number #{serial_number} doesn't exists for #{@ca_dn}" if revocation_status.nil?
        revocation_status if revocation_status[:reason].to_i != -1
      end

      # NOTE that these entries aren't being ordered by issuance, but by the latest to expire, i.e. the latest cert to expire is returned first.
      def get_all_certs(ejbca_username)
        certs = ws_call(:find_certs,
                        arg0: ejbca_username,
                        arg1: false,
        )
        Enumerator.new do |yielder|
          certs.each do |cert|
            cert_as_der = Client.double_decode64(cert[:certificate_data])
            yielder << Certificate.new(cert_as_der)
          end
        end
      end

      def self.double_decode64(b64)
        b64 = Base64.decode64(b64)
        Base64.decode64(b64)
      end

      private

      def query_ca_dn(ca_name)
        ca_chain = ws_call(:get_last_ca_chain, arg0: ca_name)
        ca_cert = Client.double_decode64(ca_chain[0][:certificate_data])
        ca_cert = OpenSSL::X509::Certificate.new(ca_cert)
        ca_cert.subject.to_s(OpenSSL::X509::Name::RFC2253)
      end

      def ws_call(operation_name, message)
        response = @client.call(operation_name, soap_action: false, message: message)
        response.to_hash["#{operation_name}_response".to_sym][:return]
      end

    end
  end
end
