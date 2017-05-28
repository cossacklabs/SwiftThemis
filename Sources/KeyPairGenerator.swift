import SwiftCThemis

public enum KeyPairGeneratorError: Error {
    case error
}

public class KeyPairGenerator{

       public init(){}
       
       public func gen() throws -> (private_key: [UInt8], public_key: [UInt8]){
              var res: Int32
              var private_key_length: Int = 0
              var public_key_length: Int = 0

              // private and public keys length determination
              res = themis_gen_ec_key_pair(nil, &private_key_length, nil, &public_key_length)
              if res != SOTER_BUFFER_TOO_SMALL {
                 throw KeyPairGeneratorError.error
              }

              // private and public key memory allocation
              let private_key = [UInt8](repeating: 0, count: private_key_length)
              let public_key = [UInt8](repeating: 0, count: public_key_length)

              // private and public keys generation
              res = themis_gen_ec_key_pair(UnsafeMutablePointer(mutating: private_key), &private_key_length, UnsafeMutablePointer(mutating: public_key), &public_key_length)
              if res != SOTER_SUCCESS {
                 throw KeyPairGeneratorError.error
              }
              return (private_key, public_key)
       } 
}
