import SwiftThemis
import Foundation


func SecureCellExample(){
    let password : String = "Password"
    let message : String = "Test message"
    let context : String = "Test context"


    do{


//Secure Cell in default mode (Seal)
        let cell = SecureCell.init(key: Array(password.utf8))

  //without context
        let cell_enc = try cell.encrypt(data: Array(message.utf8))
        print(String(bytes: try cell.decrypt(enc_data: cell_enc.data), encoding: .utf8)!)
  //with context
        let cell_with_context_enc = try cell.encrypt(data: Array(message.utf8), context: Array(context.utf8))
        print(String(bytes: try cell.decrypt(enc_data: cell_with_context_enc.data, context: Array(context.utf8)), encoding: .utf8)!)

//Secure Cell in Seal mode
        let cell_seal = SecureCell.init(key: Array(password.utf8), mode: SecureCellMode.seal)

  //without context
        let cell_seal_enc = try cell_seal.encrypt(data: Array(message.utf8))
        print(String(bytes: try cell_seal.decrypt(enc_data: cell_seal_enc.data), encoding: .utf8)!)
  //with context
        let cell_seal_with_context_enc = try cell_seal.encrypt(data: Array(message.utf8), context: Array(context.utf8))
        print(String(bytes: try cell_seal.decrypt(enc_data: cell_seal_with_context_enc.data, context: Array(context.utf8)), encoding: .utf8)!)

//Secure Cell in Token Protect mode
        let cell_token_protect = SecureCell.init(key: Array(password.utf8), mode: SecureCellMode.token_protect)

  //without context
        let cell_token_protect_enc = try cell_token_protect.encrypt(data: Array(message.utf8))
        print(String(bytes: try cell_token_protect.decrypt(enc_data: cell_token_protect_enc.data, token: cell_token_protect_enc.token), encoding: .utf8)!)
  //with context
        let cell_token_protect_with_context_enc = try cell_token_protect.encrypt(data: Array(message.utf8), context: Array(context.utf8))
        print(String(bytes: try cell_token_protect.decrypt(enc_data: cell_token_protect_with_context_enc.data, token: cell_token_protect_with_context_enc.token, context: Array(context.utf8)), encoding: .utf8)!)

//Secure Cell in Context Imprint mode
        let cell_context_imprint = SecureCell.init(key: Array(password.utf8), mode: SecureCellMode.context_imprint)

  //without context 
        //not supported

  //with context
        let cell_context_imprint_enc = try cell_context_imprint.encrypt(data: Array(message.utf8), context: Array(context.utf8))
        print(String(bytes: try cell_context_imprint.decrypt(enc_data: cell_context_imprint_enc.data, context: Array(context.utf8)), encoding: .utf8)!)


    }catch {
       print("error")
    }
}
