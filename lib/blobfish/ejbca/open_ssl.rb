# Specializations for OpenSSL module classes.
module Blobfish
  module Ejbca
    class EjbcaAwareCertificate < OpenSSL::X509::Certificate
      def serial_hex
        serial.to_s(16)
      end

      def issuer
        EjbcaAwareName.new(super)
      end
    end

    class EjbcaAwareName < OpenSSL::X509::Name
      EJBCA = 1
      def to_s(format)
        if format == EJBCA
          # TODO identify the exact format expected by EJBCA and try to produce the same from here.
          # Currently to_utf8 (see OpenSSL for Ruby, ext/openssl/ossl_x509name.c, ossl_x509name_to_utf8) is chosen because (until now) it has been observed that it generates a DN compatible with the one expected by EJBCA. Some examples of tested compatibility:
          # - "CN=Some(Non-breaking space character)CA" is encoded literally as EJBCA WS expects it instead of, for example, "CN=Some\C2\A0CA", which to_s(OpenSSL::X509::Name::RFC2253) would produce.
          self.to_utf8
        else
          super
        end
      end
    end
  end
end
