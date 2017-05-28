import SwiftThemis
import Foundation

func SecureSessionExample(){

    let messageData : String = "Test message"

    do{
//KeyPairGenerator
	let key_pair_gen = KeyPairGenerator.init()
        let alice_keys = try key_pair_gen.gen()
        let bob_keys = try key_pair_gen.gen()

//SecureSession
        let session_alice = try SecureSession.init(id: Array("Alice".utf8), private_key: alice_keys.private_key, getPubKeyCallback: {(id: [UInt8]) -> [UInt8]? in
            print(String(bytes: id, encoding: .utf8)!)
            if String(bytes: id, encoding: .utf8)! == "Bob" {
               return bob_keys.public_key
            }
            return nil
        })
        let session_bob = try SecureSession.init(id: Array("Bob".utf8), private_key: bob_keys.private_key, getPubKeyCallback: {(id: [UInt8]) -> [UInt8]? in
            print(String(bytes: id, encoding: .utf8)!)
            if String(bytes: id, encoding: .utf8)! == "Alice" {
               return alice_keys.public_key
            }
            return nil
        })

        var data = try session_alice.connectRequest()

        var unwrap_data = try session_bob.unwrap(data: data)

        unwrap_data = try session_alice.unwrap(data: unwrap_data.data!)

        unwrap_data = try session_bob.unwrap(data: unwrap_data.data!)

        unwrap_data = try session_alice.unwrap(data: unwrap_data.data!)

        if (session_alice.isEstablished) || (session_bob.isEstablished) {
                data = try session_alice.wrap(data: Array(messageData.utf8))
                unwrap_data = try session_bob.unwrap(data: data)
                print(String(bytes: unwrap_data.data!, encoding: .utf8)!)
        } else {
                print("error")
        }
    }catch {
       print("error")
    }
}
