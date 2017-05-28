import SwiftCThemis

public enum ThemisError: Error {
    case error
}

public enum SecureCellMode{
    case seal
    case token_protect
    case context_imprint
}

public class SecureCell {
    var key : [UInt8]
    var mode = SecureCellMode.seal

    public init(key: [UInt8], mode : SecureCellMode = SecureCellMode.seal) {
	self.key = key
	self.mode = mode
    }

    public func encrypt(data: [UInt8], context: [UInt8]? = nil) throws -> (data: [UInt8], token: [UInt8]?) {
	var res: Int32 = SOTER_FAIL
	var enc_data_length : Int = 0
	var token_length : Int = 0
	var context_:UnsafePointer<UInt8>? = nil
	var context_length = 0
	if context != nil {
	    context_ = UnsafePointer(context!)
	    context_length = context!.count
	}
	switch self.mode {
	    case .seal:
		res = themis_secure_cell_encrypt_seal(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(data), data.count, nil, &enc_data_length)
	    case .token_protect:
		res = themis_secure_cell_encrypt_token_protect(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(data), data.count, nil, &token_length, nil, &enc_data_length)
	    case .context_imprint:
		res = themis_secure_cell_encrypt_context_imprint(UnsafePointer(self.key), self.key.count, UnsafePointer(data), data.count, context_, context_length, nil, &enc_data_length)
	}
	if res != SOTER_BUFFER_TOO_SMALL {
		throw ThemisError.error
	}
	let enc_data = [UInt8](repeating: 0, count: enc_data_length)
	var token : [UInt8]? = nil 
	if token_length > 0 {
	    token = [UInt8](repeating: 0, count: token_length)
	}
	switch self.mode {
	    case .seal:
		res = themis_secure_cell_encrypt_seal(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
	    case .token_protect:
		res = themis_secure_cell_encrypt_token_protect(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: token!), &token_length, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
	    case .context_imprint:
		res = themis_secure_cell_encrypt_context_imprint(UnsafePointer(self.key), self.key.count, UnsafePointer(data), data.count, context_, context_length, UnsafeMutablePointer(mutating: enc_data), &enc_data_length)
	}
	if res != SOTER_SUCCESS {
		throw ThemisError.error
	}
	return (enc_data, token)
    }

    public func decrypt(enc_data: [UInt8], token: [UInt8]? = nil, context: [UInt8]? = nil) throws -> [UInt8] {
	var res: Int32 = SOTER_FAIL
	var data_length : Int = 0
	var context_:UnsafePointer<UInt8>? = nil
	var context_length = 0
	if context != nil {
	    context_ = UnsafePointer(context!)
	    context_length = context!.count
	}
	switch self.mode {
	    case .seal:
		res = themis_secure_cell_decrypt_seal(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(enc_data), enc_data.count, nil, &data_length)
	    case .token_protect:
                 if token != nil {
                 	res = themis_secure_cell_decrypt_token_protect(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(enc_data), enc_data.count, UnsafePointer(token!), token!.count, nil, &data_length)
                 }   
	    case .context_imprint:
		res = themis_secure_cell_decrypt_context_imprint(UnsafePointer(self.key), self.key.count, UnsafePointer(enc_data), enc_data.count, context_, context_length, nil, &data_length)
	}
	if res != SOTER_BUFFER_TOO_SMALL {
		throw ThemisError.error
	}
	let data = [UInt8](repeating: 0, count: data_length)
	switch self.mode {
	    case .seal:
		res = themis_secure_cell_decrypt_seal(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(enc_data), enc_data.count, UnsafeMutablePointer(mutating: data), &data_length)
	    case .token_protect:
                 if token != nil {
                 	res = themis_secure_cell_decrypt_token_protect(UnsafePointer(self.key), self.key.count, context_, context_length, UnsafePointer(enc_data), enc_data.count, UnsafePointer(token!), token!.count, UnsafeMutablePointer(mutating: data), &data_length)
                 }   
	    case .context_imprint:
		res = themis_secure_cell_decrypt_context_imprint(UnsafePointer(self.key), self.key.count, UnsafePointer(enc_data), enc_data.count, context_, context_length, UnsafeMutablePointer(mutating: data), &data_length)
	}
	if res != SOTER_SUCCESS {
		throw ThemisError.error
	}
	return data
    }

}
