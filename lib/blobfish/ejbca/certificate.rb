
module Blobfish
  module Ejbca
    # TODO evaluate to extract this class to a new Blobfish's crypto utilities gem.
    class Certificate < OpenSSL::X509::Certificate
      def serial_hex
        serial.to_s(16)
      end
    end
  end
end