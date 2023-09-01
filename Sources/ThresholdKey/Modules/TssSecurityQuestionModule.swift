import Foundation
#if canImport(lib)
    import lib
#endif
import BigInt

let TssSecurityQuestion = "TssSecurityQuestion"

public struct TssSecurityQuestionData : Codable{
    let nonce: String
    let question: String
    let description: String
}

// Security question has low entrophy, hence it is not recommended way to secure the factor key or share
public final class TssSecurityQuestionModule {
    // set question
    public static func set_security_question( threshold : ThresholdKey, factorKey :String, question: String, answer: String, description: String, tag: String) throws {
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
        
        let factorBigInt = BigInt( sign: .plus, magnitude: BigUInt(Data(hex: factorKey)))
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "invalid answer format"
        }
        let hashBigInt = BigInt( sign: .plus, magnitude: BigUInt(hash))
        
        let nonceBigInt = factorBigInt - hashBigInt
        let nonce = nonceBigInt.serialize().toHexString()
        print(nonce)
        
        // set to metadata using nonce, question, description, tag
        let data = TssSecurityQuestionData(nonce: nonce, question: question, description: description)
        
        let jsonData = try JSONEncoder().encode(data)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )

    }
    
    public static func delete_security_question( threshold : ThresholdKey, tag: String) throws {
        //
        let domainKey = TssSecurityQuestion + ":" + tag
        var isSet = false
        do {
            let question = try TssSecurityQuestionModule.get_question(threshold: threshold, tag: tag)
            if question.count > 0 {
                isSet = true
            }
        } catch {}
        
        if !isSet {throw "Security Question is not set"}
        
        let data : [String:String] = [:]
        
        let jsonData = try JSONEncoder().encode(data)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )
    }
    
    // get question
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
    
    // getFactorKey
    public static func get_factor_key ( threshold: ThresholdKey, answer: String , tag: String ) throws -> String {
        // get data format from json
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        
        let jsonObj = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        
        // hash answer
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "invalid answer format"
        }
        let hashBigInt = BigInt( sign: .plus, magnitude: BigUInt(hash))
        
        let nonce = BigInt(Data(hex: jsonObj.nonce))
        
        // get factorkey by adding answer hasn and nonce
        let factorkeyBigInt = hashBigInt + nonce
        
        return factorkeyBigInt.serialize().toHexString()
    }
    
    
    public static func input_share ( threshold :ThresholdKey, answer: String, tag: String) async throws -> String {
        let factorKey = try TssSecurityQuestionModule.get_factor_key(threshold: threshold, answer: answer, tag: tag)
        
        try await threshold.input_factor_key(factorKey: factorKey)
        return factorKey
    }
    
}
