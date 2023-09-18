import Foundation
#if canImport(lib)
    import lib
#endif
import BigInt

let TssSecurityQuestion = "tssSecurityQuestion"


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
    public var question: String
    
    public func toJsonString() throws -> String {
        let jsonData = try JSONEncoder().encode(self)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        return jsonStr
    }
    
    public static func fromJsonString(jsonStr: String ) throws -> Self {
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        let store = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        return store
    }
}

// Security question has low entrophy, hence it is not recommended way to secure the factor key or share
public final class TssSecurityQuestionModule {
    public static func compute_hash( threshold : ThresholdKey, answer: String, tag: String ) throws -> String {
        let suffix = try threshold.get_key_details().pub_key.getPublicKey(format: .EllipticCompress) + tag
        let prehash = answer + suffix
        guard let hash = prehash.data(using: .utf8)?.sha3(.keccak256) else {
            throw "Invalid answer format for answer : \(answer)"
        }
        return hash.toHexString()
    }
    
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
    public static func set_security_question( threshold : ThresholdKey, question: String, answer: String, factorKey :String, tag: String ) async throws -> String {
        
        let domainKey = TssSecurityQuestion + ":" + tag
        
        var isSet = false
        do {
            let question = try TssSecurityQuestionModule.get_question(threshold: threshold, tag: tag)
            if question.count > 0 {
                isSet = true
            }
        } catch {}
        
        if isSet {throw "Trying to set Security Question again"}
        
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)

        let hashKey = PrivateKey(hex: hash)
        let hashPub = try hashKey.toPublic();
        
        let shareIndex: Int32 = 3
        
        let data = TssSecurityQuestionData( shareIndex: String(shareIndex), factorPublicKey: hashPub, question: question )
        try threshold.set_general_store_domain(key: domainKey, data: data.toJsonString() )
        
        // register
        try await TssModule.register_factor(threshold_key: threshold, tss_tag: tag, factor_key: factorKey, new_factor_pub: hashPub, new_tss_index: shareIndex)
        let deviceShareIndex = try await TssModule.find_device_share_index(threshold_key: threshold, factor_key: factorKey)
        
        try TssModule.backup_share_with_factor_key(threshold_key: threshold, shareIndex: deviceShareIndex, factorKey: hash)
        
        return hash
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
    public static func change_security_question( threshold : ThresholdKey, newQuestion: String, newAnswer: String, answer: String, tag: String) async throws -> (String, String){
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let storeStr = try threshold.get_general_store_domain(key: domainKey)
        var store = try TssSecurityQuestionData.fromJsonString(jsonStr: storeStr)
        
        // hash answer and new answer
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)
        let newHash = try compute_hash(threshold: threshold, answer: newAnswer, tag: tag)
        
        let hashKey = PrivateKey(hex: hash)
        let hashPub = try hashKey.toPublic();
        
        let newHashKey = PrivateKey(hex: newHash)
        let newHashPub = try newHashKey.toPublic();
        
        // create new factor using newHash
        let (tssIndex, _) = try await TssModule.get_tss_share(threshold_key: threshold, tss_tag: tag, factorKey: hash)
        try await TssModule.register_factor(threshold_key: threshold, tss_tag: tag, factor_key: hash, new_factor_pub: newHashPub, new_tss_index: Int32(tssIndex)!)
        let deviceShareIndex = try await TssModule.find_device_share_index(threshold_key: threshold, factor_key: hash)
        try TssModule.backup_share_with_factor_key(threshold_key: threshold, shareIndex: deviceShareIndex, factorKey: newHash)
        
        // delete old hash factor
        try await TssModule.delete_factor_pub(threshold_key: threshold, tss_tag: tag, factor_key: hash, delete_factor_pub: hashPub)
        // delete share metadata
        
        
        store.question = newQuestion
        store.factorPublicKey = newHashPub
        
        // set updated data to domain store
        let jsonStr = try store.toJsonString()
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )
        
        try await threshold.sync_metadata();
        
        return (hash, newHash)
    }
    
    /// delete security question
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tag: tss tag
    ///
    /// - Returns: `String` public key of the factor
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to delete security question
    public static func delete_security_question( threshold : ThresholdKey, tag: String, factorKey: String) async throws -> String  {
        //
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        let jsonObj = try TssSecurityQuestionData.fromJsonString(jsonStr: jsonStr)
        
        if jsonObj.question.count == 0 {
            throw "Security Question is not set"
        }
        let deleteFactorPub = jsonObj.factorPublicKey

        // replace with delete store domain 
        // sync_metadata is not required as delete_factor_pub will sync metadata
        let jsonStr1 = "{}"
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr1 )
        
        try await TssModule.delete_factor_pub(threshold_key: threshold, tss_tag: tag, factor_key: factorKey, delete_factor_pub: deleteFactorPub)
        
        return deleteFactorPub
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
        let jsonObj = try TssSecurityQuestionData.fromJsonString(jsonStr: jsonStr)
        
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
        let store = try TssSecurityQuestionData.fromJsonString(jsonStr: jsonStr)

        // hash answer
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)
        let factorPub = try PrivateKey(hex: hash).toPublic(format: .EllipticCompress);
        if (factorPub != store.factorPublicKey) {
            throw "Invalid Answer"
        }
        
        return hash
    }
}
