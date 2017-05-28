import SwiftCThemis

enum SecureSessionError: Error{
     case initialisationError
     case lengthDeterminationError
     case error
}

public enum SecureSessionStatus{
     case success
     case sendOutputToPeer
}


typealias GetPubKeyCallback = @convention(c) (UnsafeRawPointer?, Int, UnsafeMutableRawPointer?, Int, UnsafeMutableRawPointer?) -> Int32

struct SecureSessionCallbacks{
       var getPubKeyCallback : ([UInt8]) -> [UInt8]?       
}

let get_pub_key_callback : GetPubKeyCallback = { (idPtr: UnsafeRawPointer?, idLen: Int, keyPtr: UnsafeMutableRawPointer?, keyLen: Int, userData: UnsafeMutableRawPointer?) -> Int32 in
    if idPtr == nil || idLen == 0 || keyPtr == nil || keyLen == 0 || userData == nil {
       return THEMIS_FAIL
    }
    let ssc : SecureSessionCallbacks = userData!.assumingMemoryBound(to: SecureSessionCallbacks.self).pointee
    let key = ssc.getPubKeyCallback(Array(UnsafeBufferPointer(start: idPtr!.assumingMemoryBound(to: UInt8.self), count: idLen)))
    if key == nil || key!.count > keyLen {
       return THEMIS_FAIL
    }
    memcpy(keyPtr!, UnsafePointer(key!), key!.count)
    return SOTER_SUCCESS
}



public class SecureSession{
       var ssc: SecureSessionCallbacks
       var transport: secure_session_user_callbacks_t?
       var session: OpaquePointer?

       public var isEstablished: Bool {
           if session != nil {
              return secure_session_is_established(session)       
           }
           return false
       }

       public init(id: [UInt8], private_key: [UInt8], getPubKeyCallback: @escaping ([UInt8]) -> [UInt8]?) throws {
              self.ssc = SecureSessionCallbacks(getPubKeyCallback: getPubKeyCallback)
              transport = secure_session_user_callbacks_t(send_data: nil, receive_data: nil, state_changed: nil, get_public_key_for_id: get_pub_key_callback, user_data: &(self.ssc))
              session = secure_session_create(UnsafePointer(id), id.count, UnsafePointer(private_key), private_key.count, &transport!)
              if session == nil{
                 throw SecureSessionError.initialisationError
              }
       }

       public func connectRequest() throws -> [UInt8] {
              var buf_length : Int = 0
              var res = secure_session_generate_connect_request(session, nil, &buf_length)
              if res != THEMIS_BUFFER_TOO_SMALL {
                 throw SecureSessionError.lengthDeterminationError
              }
              let buf = [UInt8](repeating: 0, count: buf_length)
              res = secure_session_generate_connect_request(session, UnsafeMutablePointer(mutating: buf), &buf_length)
              if res != THEMIS_SUCCESS {
                 throw SecureSessionError.error
              }
              return buf
       }

       public func wrap(data: [UInt8]) throws -> [UInt8] {
              var buf_length : Int = 0
              var res = secure_session_wrap(session, UnsafePointer(data), data.count, nil, &buf_length)
              if res != THEMIS_BUFFER_TOO_SMALL {
                 throw SecureSessionError.lengthDeterminationError
              }
              let buf = [UInt8](repeating: 0, count: buf_length)
              res = secure_session_wrap(session, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: buf), &buf_length)
              if res != THEMIS_SUCCESS {
                 throw SecureSessionError.error
              }
              return buf
       }

       public func unwrap(data: [UInt8]) throws -> (status: SecureSessionStatus, data: [UInt8]?) {
              var buf_length : Int = 0
              var res = secure_session_unwrap(session, UnsafePointer(data), data.count, nil, &buf_length)
              if res == THEMIS_SUCCESS {
                 return (SecureSessionStatus.success, nil)
              }
              if res != THEMIS_BUFFER_TOO_SMALL {
                 throw SecureSessionError.lengthDeterminationError
              }
              let buf = [UInt8](repeating: 0, count: buf_length)
              res = secure_session_unwrap(session, UnsafePointer(data), data.count, UnsafeMutablePointer(mutating: buf), &buf_length)
              switch res{
                     case THEMIS_SUCCESS:
                          return (SecureSessionStatus.success, buf)
                     case THEMIS_SSESSION_SEND_OUTPUT_TO_PEER:
                          return (SecureSessionStatus.sendOutputToPeer, buf)
                     default:
                          throw SecureSessionError.error
              }
       }

       deinit {
              secure_session_destroy(session)
       }

}
