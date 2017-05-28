import SwiftThemis
import Foundation

func SecureMessageExample(){

    let messageData : String = "Test message"


    do{

//KeyPairGenerator
        let key_pair_gen = KeyPairGenerator.init()
        let key_pair = try key_pair_gen.gen()
        let peer_key_pair = try key_pair_gen.gen()

//SecureMessage
        let message = SecureMessage.init(private_key: key_pair.private_key, peer_public_key: peer_key_pair.public_key)
        let peer_message = SecureMessage.init(private_key: peer_key_pair.private_key, peer_public_key: key_pair.public_key)

//signing
        let signed_message = try message.sign(data: Array(messageData.utf8))
        print(String(bytes: try peer_message.verify(data: signed_message), encoding: .utf8)!)

//encrypting
        let encrypted_message = try message.encrypt(data: Array(messageData.utf8))
        print(String(bytes: try peer_message.decrypt(data: encrypted_message), encoding: .utf8)!)
    }catch {
       print("error")
    }
}
