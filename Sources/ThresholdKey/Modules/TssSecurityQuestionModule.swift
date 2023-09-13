import Foundation
#if canImport(lib)
    import lib
#endif
import BigInt

let TssSecurityQuestion = "TssSecurityQuestion"


public struct EncryptedMessage : Codable {
    public let ciphertext: String;
    public let ephemPublicKey: String;
    public let iv: String;
    public let mac: String;
    
    public func toString() throws -> String {
        let data = try JSONEncoder().encode(self)
//        let data = try JSONSerialization.data(withJSONObject: self)
        guard let result = String(data: data, encoding: .utf8) else {
            throw "invalid toString"
        }
        return result
    }
}

public struct TssSecurityQuestionData : Codable{
    public var shareIndex: String
    public var factorPublicKey: String
    public var associatedFactor: EncryptedMessage
    public var question: String
}

// Security question has low entrophy, hence it is not recommended way to secure the factor key or share
public final class TssSecurityQuestionModule {
    
    /// set security question
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - question: The security question.
    ///   - answer: The answer for the security question.
    ///   - factorKey: Factor key that registred to security question
    ///   - tag: tss tag
    ///
    /// - Returns: ``
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key of failed to set security question
    public static func set_security_question( threshold : ThresholdKey, question: String, answer: String, factorKey :String, tag: String ) async throws {
        //
        let domainKey = TssSecurityQuestion + ":" + tag
        
        var isSet = false
        do {
            let question = try TssSecurityQuestionModule.get_question(threshold: threshold, tag: tag)
            if question.count > 0 {
                isSet = true
            }
        } catch {}
        
        if isSet {throw "Trying to set Security Question again"}
        
        
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "Invalid answer format"
        }
        
        let hashKey = PrivateKey(hex: hash.toHexString())
        let hashPub = try hashKey.toPublic();
        guard let encryptedData = try encrypt(key: hashPub, msg: factorKey).data(using: .utf8) else {
            throw "encryption error"
        }
        
        let encryptedMsg = try JSONDecoder().decode(EncryptedMessage.self, from: encryptedData)

        let factorPub = try PrivateKey(hex: factorKey).toPublic(format: .EllipticCompress)
        
        let shareIndex = "3"
        
        let data = TssSecurityQuestionData( shareIndex: shareIndex, factorPublicKey: factorPub, associatedFactor: encryptedMsg, question: question )
        
        
        let jsonData = try JSONEncoder().encode(data)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )
        
        try await threshold.sync_metadata();
    }
    
    
    /// change security question to new question and answer
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - newQuestion: The new security question .
    ///   - newAnswer: The new answer for the security question.
    ///   - answer: current answer
    ///   - tag: tss tag
    ///
    /// - Returns: ``
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to change security question
    public static func change_security_question( threshold : ThresholdKey, newQuestion: String, newAnswer: String, answer: String, tag: String) async throws {
        let domainKey = TssSecurityQuestion + ":" + tag
        
        var isSet = false
        do {
            let question = try TssSecurityQuestionModule.get_question(threshold: threshold, tag: tag)
            if question.count > 0 {
                isSet = true
            }
        } catch {}
        
        if !isSet {throw "Security Question is not set"}
        
        // hash answer and new answer
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "Invalid answer format"
        }

        guard let newHash = newAnswer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "Invalid answer format"
        }
        
        // get and decrypt factorkey and encrypt with new hash
        guard let storeData = try threshold.get_general_store_domain(key: domainKey).data(using: .utf8) else {
            throw "Invalid format"
        }
        var store = try JSONDecoder().decode(TssSecurityQuestionData.self, from: storeData)
        
        let associatedFactor = try decrypt(key: hash.toHexString(), msg: store.associatedFactor.toString() )
        
        let newHashKey = PrivateKey(hex: newHash.toHexString())
        let newHashPub = try newHashKey.toPublic();
        guard let encryptedData = try encrypt(key: newHashPub, msg: associatedFactor).data(using: .utf8) else {
            throw "encryption error"
        }
        let encryptedMsg = try JSONDecoder().decode(EncryptedMessage.self, from: encryptedData)
        
        store.question = newQuestion
        store.associatedFactor = encryptedMsg
        
        // set updated data to domain store
        let jsonData = try JSONEncoder().encode(store)
        
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )
        
        try await threshold.sync_metadata();

    }
    
    /// delete security question
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tag: tss tag
    ///
    /// - Returns: `String` public key of the factor
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to delete security question
    public static func delete_security_question( threshold : ThresholdKey, tag: String) async throws -> String  {
        //
        let domainKey = TssSecurityQuestion + ":" + tag
        var isSet = false
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        let jsonObj = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        if jsonObj.question.count > 0 {
            isSet = true
        }
        if !isSet {throw "Security Question is not set"}
        let factorPub = jsonObj.factorPublicKey
        
        let emptyData : [String:String] = [:]
        
        let jsonData = try JSONEncoder().encode(emptyData)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )
        
        try await threshold.sync_metadata();
        return factorPub
    }
    
    
    /// get security question
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tag: tss tag
    ///
    /// - Returns: `String` question
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to get security question
    public static func get_question( threshold: ThresholdKey,  tag: String ) throws -> String {
        // get data format from json
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        let jsonObj = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        
        return jsonObj.question
    }
            
    
    /// recover security question's factor given correct answer
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - answer: answer to security question
    ///   - tag: tss tag
    ///
    /// - Returns: `String` factor key
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to delete security question
    public static func recover_factor ( threshold: ThresholdKey, answer: String , tag: String ) throws -> String {
        // get data format from json
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        
        let store = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        
        // hash answer
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "invalid answer format"
        }
        let associatedFactor = try decrypt(key: hash.toHexString(), msg: store.associatedFactor.toString() )
        
        // get factorkey by adding answer hasn and nonce
        return associatedFactor
    }
}
