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
    public static func setSecurityQuestion( threshold : ThresholdKey, factorKey :String, question: String, answer: String, description: String, tag: String) throws {
        //
        let factorBigInt = BigInt( sign: .plus, magnitude: BigUInt(Data(hex: factorKey)))
        guard let hash = answer.data(using: .utf8)?.sha3(.keccak256) else {
            throw "invalid answer format"
        }
        let hashBigInt = BigInt( sign: .plus, magnitude: BigUInt(hash))
        
        let nonceBigInt = factorBigInt - hashBigInt
        let nonce = nonceBigInt.serialize().toHexString()
        
        let domainKey = TssSecurityQuestion + ":" + tag
        // set to metadata using nonce, question, description, tag
        let data = TssSecurityQuestionData(nonce: nonce, question: question, description: description)
        print(data)
        let jsonData = try JSONEncoder().encode(data)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw "Invalid security question data"
        }
        try threshold.set_general_store_domain(key: domainKey, data: jsonStr )

    }
    
    // get question
    public static func getSecurityQuestion( threshold: ThresholdKey,  tag: String ) throws -> String {
        // get data format from json
        let domainKey = TssSecurityQuestion + ":" + tag
        
        let jsonStr = try threshold.get_general_store_domain(key: domainKey)
        print(jsonStr)
        guard let data = jsonStr.data(using: .utf8) else {
            throw "invalid security question data"
        }
        let jsonObj = try JSONDecoder().decode( TssSecurityQuestionData.self, from: data)
        
        return jsonObj.question
    }
    
    // getFactorKey
    public static func getFactorKey ( threshold: ThresholdKey, answer: String , tag: String ) throws -> String {
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
}
