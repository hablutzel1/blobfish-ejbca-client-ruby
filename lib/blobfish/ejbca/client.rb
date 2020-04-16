
require 'savon'
require 'base64'
require_relative 'certificate'

module Blobfish
  module Ejbca

    # See too 'D:\d\ejbca\tests\ejbca_ws_client\src\p12onejbcaside' for a Java alternative for this client.
    class Client
      STATUS_NEW = 10
      TOKEN_TYPE_P12 = 'P12'
      TOKEN_TYPE_USERGENERATED = 'USERGENERATED'
      RESPONSETYPE_CERTIFICATE = 'CERTIFICATE'
      REVOCATION_REASON_UNSPECIFIED = 0

      # @param [String] ws_additional_trusted_anchors e.g. +ca-certificates.crt+. Required only if +wsdl_url+ uses a non-commercial SSL certificate, otherwise it should be +nil+.
      def initialize(wsdl_url, ws_additional_trusted_anchors, ws_client_certificate, ws_client_key, ws_client_key_password, ca_name, cert_profile, ee_profile)
        @savon_client = Savon.client(
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

      def self.escape_dn_attr_value(val)
        # TODO study escaping rules in detail. Take a look at relevant standards and the EJBCA implementation. See too https://sourceforge.net/p/ejbca/discussion/123123/thread/d36bb985/.
        val.gsub(",", "\\,")
      end

      # Note that it requires 'Allow validity override' set in the EJBCA certificate profile for the pair +validity_type,validity_value+ to be effective.
      # 'subject_dn' should have its attributes values escaped using 'escape_dn_attr_value'.
      # 'custom_friendly_name' is optional. It can be set to 'nil' to maintain the one set by EJBCA (TODO confirm if EJBCA actually sets a friendly name).
      def request_pfx(ejbca_username, email_address, subject_dn, subject_alt_name, validity_type, validity_value, pfx_password, custom_friendly_name)
        end_user = create_end_user(ejbca_username, pfx_password, TOKEN_TYPE_P12, email_address, subject_dn, subject_alt_name, validity_type, validity_value)
        ws_call(:edit_user,
                arg0: end_user)
        ws_resp = ws_call(:pkcs12_req,
                          arg0: ejbca_username,
                          arg1: pfx_password,
                          arg3: '2048',
                          arg4: 'RSA'
        )
        pfx_bytes = Client.double_decode64(ws_resp[:keystore_data])
        pkcs12 = OpenSSL::PKCS12.new(pfx_bytes, pfx_password)
        unless custom_friendly_name.nil?
          # NOTE that this is currently removing the friendlyName for all bundled CA certs, but this is not expected to produce problems.
          updated_pkcs12 = OpenSSL::PKCS12.create(pfx_password, custom_friendly_name, pkcs12.key, pkcs12.certificate, pkcs12.ca_certs)
          pfx_bytes = updated_pkcs12.to_der
        end
        {pfx: pfx_bytes, cert: Certificate.new(pkcs12.certificate)}

      end

      def request_from_csr(pem_csr, ejbca_username, email_address, subject_dn, subject_alt_name, validity_type, validity_value)
        end_user = create_end_user(ejbca_username, nil, TOKEN_TYPE_USERGENERATED, email_address, subject_dn, subject_alt_name, validity_type, validity_value)
        ws_resp = ws_call(:certificate_request,
                          arg0: end_user,
                          arg1: pem_csr,
                          arg2: 0,
                          arg4: RESPONSETYPE_CERTIFICATE)
        cert_as_der = Client.double_decode64(ws_resp[:data])
        Certificate.new(cert_as_der)
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

      private

      def create_end_user(ejbca_username, password, token_type, email_address, subject_dn, subject_alt_name, validity_type, validity_value)
        end_user = {}
        end_user[:username] = ejbca_username
        # When password is nil, the element is excluded from the hash, otherwise it would produce <password xsi:nil="true"/> which is interpreted as "" in the EJBCA side. See https://github.com/savonrb/gyoku/#user-content-hash-values.
        end_user[:password] = password unless password == nil
        end_user[:status] = STATUS_NEW
        end_user[:token_type] = token_type
        end_user[:email] = email_address
        end_user[:subjectDN] = subject_dn
        end_user[:subject_alt_name] = subject_alt_name
        end_user[:ca_name] = @ca_name
        end_user[:certificate_profile_name] = @cert_profile
        end_user[:end_entity_profile_name] = @ee_profile
        if validity_type == :days_from_now
          custom_endtime = "#{validity_value}:0:0"
        elsif validity_type == :fixed_not_after
          unless validity_value.is_a? Time
            raise ArgumentError
          end
          not_after = validity_value.utc
          custom_endtime = not_after.strftime('%Y-%m-%d %H:%M')
        else
          raise NotImplementedError
        end
        end_user[:extended_information] = [{name: 'customdata_ENDTIME', value: custom_endtime}]
        end_user
      end

      def self.double_decode64(b64)
        b64 = Base64.decode64(b64)
        Base64.decode64(b64)
      end

      def query_ca_dn(ca_name)
        ca_chain = ws_call(:get_last_ca_chain, arg0: ca_name)
        ca_cert = ca_chain.kind_of?(Array) ? ca_chain[0] : ca_chain
        ca_cert = Client.double_decode64(ca_cert[:certificate_data])
        ca_cert = OpenSSL::X509::Certificate.new(ca_cert)
        ca_cert.subject.to_s(OpenSSL::X509::Name::RFC2253)
      end

      def ws_call(operation_name, message)
        response = @savon_client.call(operation_name, soap_action: false, message: message)
        response.to_hash["#{operation_name}_response".to_sym][:return]
      end

    end
  end
end
