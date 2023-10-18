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
    public static func set_security_question( threshold : ThresholdKey, question: String, answer: String, factorKey :String, selectedServer:String, tag: String ) async throws -> String {
        
        try await TssModule.set_tss_tag(threshold_key: threshold, tss_tag: tag)
        try await TssModule.update_tss_pub_key(threshold_key: threshold, tss_tag: tag, prefetch: true)
        var errorCode: Int32 = -1
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)
        let factorKeyPtr = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)
        let questionPtr = UnsafeMutablePointer<Int8>(mutating: (question as NSString).utf8String)
        let hashPtr = UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold.curveN as NSString).utf8String)
        
        
        
        let auth_signatures_json = try JSONSerialization.data(withJSONObject: threshold.authSignatures)
        guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
            throw RuntimeError("auth signatures error")
        }
        let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)
        
        let selectedServers:[UInt32] = [1,2,3]
        let selected_servers_json = try JSONSerialization.data(withJSONObject: selectedServers as Any)
        guard let selected_servers_str = String(data: selected_servers_json, encoding: .utf8) else {
            throw RuntimeError("selectedServers error")
        }
        let serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)

//        let tssIndex: UInt32 = 2

        withUnsafeMutablePointer(to: &errorCode, { error in
            tss_security_question_set_security_question(threshold.pointer, factorKeyPtr, questionPtr, hashPtr,  2, serversPointer, authSignaturesPointer,
                                                        curvePointer,  error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey set_security_question \(errorCode)")
        }
        
        let shareIndex = try await TssModule.find_device_share_index(threshold_key: threshold, factor_key: factorKey);
        try TssModule.backup_share_with_factor_key(threshold_key: threshold, shareIndex: shareIndex, factorKey: hash)
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

        try await TssModule.set_tss_tag(threshold_key: threshold, tss_tag: tag)
        try await TssModule.update_tss_pub_key(threshold_key: threshold, tss_tag: tag, prefetch: true, incNonce: 2)
        var errorCode: Int32 = -1
        
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)
        let newHash = try compute_hash(threshold: threshold, answer: newAnswer, tag: tag)
        let newQuestionPtr = UnsafeMutablePointer<Int8>(mutating: (newQuestion as NSString).utf8String)
        let hashPtr = UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)
        let newHashPtr = UnsafeMutablePointer<Int8>(mutating: (newHash as NSString).utf8String)
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold.curveN as NSString).utf8String)
        
        let auth_signatures_json = try JSONSerialization.data(withJSONObject: threshold.authSignatures)
        guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
            throw RuntimeError("auth signatures error")
        }
        let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)
        
        let selectedServers:[UInt32] = [1,2,3]
        let selected_servers_json = try JSONSerialization.data(withJSONObject: selectedServers as Any)
        guard let selected_servers_str = String(data: selected_servers_json, encoding: .utf8) else {
            throw RuntimeError("selectedServers error")
        }
        let serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)

        withUnsafeMutablePointer(to: &errorCode, { error in
            tss_security_question_change_question(threshold.pointer, newHashPtr, newQuestionPtr, hashPtr, serversPointer, authSignaturesPointer, curvePointer,  error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey change_security_question \(errorCode)")
        }
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
    public static func delete_security_question( threshold : ThresholdKey, tag: String, factorKey: String
                                                 , answer: String? = nil) async throws -> String  {
        
        try await TssModule.set_tss_tag(threshold_key: threshold, tss_tag: tag)
        try await TssModule.update_tss_pub_key(threshold_key: threshold, tss_tag: tag, prefetch: true)

        var errorCode: Int32 = -1
        let factorKeyPtr = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)
        var hashPtr : UnsafeMutablePointer<Int8>?;
        if let answer = answer {
            let hash = try self.compute_hash(threshold: threshold, answer: answer, tag: tag)
            hashPtr =  UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)
        }
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold.curveN as NSString).utf8String)
        
        let auth_signatures_json = try JSONSerialization.data(withJSONObject: threshold.authSignatures)
        guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
            throw RuntimeError("auth signatures error")
        }
        let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)
        
        let selectedServers:[UInt32] = [1,2,3]
        let selected_servers_json = try JSONSerialization.data(withJSONObject: selectedServers as Any)
        guard let selected_servers_str = String(data: selected_servers_json, encoding: .utf8) else {
            throw RuntimeError("selectedServers error")
        }
        let serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)
        
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            tss_security_question_delete_security_question(threshold.pointer, factorKeyPtr, hashPtr, serversPointer, authSignaturesPointer, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey delete_security_question \(errorCode)")
        }
        let hash = String(cString: result!)
        string_free(result)
        return hash
    }
    
    
    /// get security question
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tag: tss tag
    ///
    /// - Returns: `String` question
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key or fail to get security question
    public static func get_question( threshold: ThresholdKey,  tag: String ) async throws -> String {
        
        try await TssModule.set_tss_tag(threshold_key: threshold, tss_tag: tag)
        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            tss_security_question_get_question(threshold.pointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_question \(errorCode)")
        }
        let question = String(cString: result!)
        string_free(result)
        return question
        
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
    public static func recover_factor ( threshold: ThresholdKey, answer: String , tag: String ) async throws -> String {
        
        try await TssModule.set_tss_tag(threshold_key: threshold, tss_tag: tag)
        var errorCode: Int32 = -1
        
        let hash = try compute_hash(threshold: threshold, answer: answer, tag: tag)
        
        let answerPtr = UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            tss_security_question_recover_factor(threshold.pointer, answerPtr, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey recover_factor \(errorCode)")
        }
        let hashOut = String(cString: result!)
        string_free(result)
        
        return hash
    }
}
