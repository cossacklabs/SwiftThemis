import SwiftCThemis

public enum SecureMessageError: Error {
       case invalidParameterError
       case lengthDeterminationError
       case error
}


public class SecureMessage{
       var private_key : [UInt8]? = nil
       var peer_public_key : [UInt8]? = nil

       public init(private_key: [UInt8]? = nil, peer_public_key: [UInt8]? = nil){
              self.private_key = private_key
              self.peer_public_key = peer_public_key
       }

       public func encrypt(data: [UInt8]) throws -> [UInt8] {
                var res: Int32 = SOTER_FAIL
	        var enc_data_length : Int = 0
                if self.private_key == nil || self.peer_public_key == nil {
                   throw SecureMessageError.invalidParameterError
                }
                res = themis_secure_message_wrap(UnsafePointer(self.private_key!), self.private_key!.count, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, nil, &enc_data_length)
                if res != SOTER_BUFFER_TOO_SMALL {
		   throw SecureMessageError.lengthDeterminationError
	        }
               	let enc_data = [UInt8](repeating: 0, count: enc_data_length)
                res = themis_secure_message_wrap(UnsafePointer(self.private_key!), self.private_key!.count, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
                if res != SOTER_SUCCESS {
		   throw SecureMessageError.error
	        }
                return enc_data
       }

       public func decrypt(data: [UInt8]) throws -> [UInt8] {
                var res: Int32 = SOTER_FAIL
	        var enc_data_length : Int = 0
                if self.private_key == nil || self.peer_public_key == nil {
                   throw SecureMessageError.invalidParameterError
                }
                res = themis_secure_message_unwrap(UnsafePointer(self.private_key!), self.private_key!.count, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, nil, &enc_data_length)
                if res != SOTER_BUFFER_TOO_SMALL {
		   throw SecureMessageError.lengthDeterminationError
	        }
               	let enc_data = [UInt8](repeating: 0, count: enc_data_length)
                res = themis_secure_message_unwrap(UnsafePointer(self.private_key!), self.private_key!.count, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
                if res != SOTER_SUCCESS {
		   throw SecureMessageError.error
	        }
                return enc_data
       }

       public func sign(data: [UInt8]) throws -> [UInt8] {
                var res: Int32 = SOTER_FAIL
	        var enc_data_length : Int = 0
                if self.private_key == nil {
                   throw SecureMessageError.invalidParameterError
                }
                res = themis_secure_message_wrap(UnsafePointer(self.private_key!), self.private_key!.count, nil, 0, UnsafePointer(data), data.count, nil, &enc_data_length)
                if res != SOTER_BUFFER_TOO_SMALL {
		   throw SecureMessageError.lengthDeterminationError
	        }
               	let enc_data = [UInt8](repeating: 0, count: enc_data_length)
                res = themis_secure_message_wrap(UnsafePointer(self.private_key!), self.private_key!.count, nil, 0, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
                if res != SOTER_SUCCESS {
		   throw SecureMessageError.error
	        }
                return enc_data
       }

       public func verify(data: [UInt8]) throws -> [UInt8] {
                var res: Int32 = SOTER_FAIL
	        var enc_data_length : Int = 0
                if self.peer_public_key == nil {
                   throw SecureMessageError.invalidParameterError
                }
                res = themis_secure_message_unwrap(nil, 0, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, nil, &enc_data_length)
                if res != SOTER_BUFFER_TOO_SMALL {
		   throw SecureMessageError.lengthDeterminationError
	        }
               	let enc_data = [UInt8](repeating: 0, count: enc_data_length)
                res = themis_secure_message_unwrap(nil, 0, UnsafePointer(self.peer_public_key!), self.peer_public_key!.count, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
                if res != SOTER_SUCCESS {
		   throw SecureMessageError.error
	        }
                return enc_data
       }

}
