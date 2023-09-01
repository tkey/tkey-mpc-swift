import XCTest
import Foundation
@testable import tkey_pkg
import Foundation

final class tkey_pkgTssSecurityQuestionModuleTests: XCTestCase {
    private var threshold_key: ThresholdKey!
    
    override func setUp() async throws {
        let postbox_key = try! PrivateKey.generate()
        let storage_layer = try! StorageLayer(enable_logging: true, host_url: "https://metadata.tor.us", server_time_offset: 2)
        let service_provider = try! ServiceProvider(enable_logging: true, postbox_key: postbox_key.hex)
        let threshold = try! ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false
        )

        _ = try! await threshold.initialize()
        threshold_key = threshold
    }
    
    override func tearDown() {
        threshold_key = nil
    }
    
    func test() async throws {
        let key_reconstruction_details = try! await threshold_key.reconstruct()
        let question = "favorite marvel character"
        let answer = "iron man"
        let answer_2 = "captain america"
        let factor_key = try? PrivateKey.generate()
        
        var allIndex = try! threshold_key.get_shares_indexes()
        allIndex.removeAll(where: {$0 == "1"})
        try! TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: allIndex[0], factorKey: factor_key!.hex)
        
        try TssSecurityQuestionModule.set_security_question(threshold: threshold_key, factorKey: factor_key!.hex, question: question, answer: answer, description: "please enter password", tag: "special")
        
        
        do {
            try TssSecurityQuestionModule.set_security_question(threshold: threshold_key, factorKey: factor_key!.hex, question: question, answer: answer_2, description: "please enter password", tag: "special")
            XCTFail("Should not able to set quesetion twice")
        } catch {}
        
        let questionReturn = try? TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        XCTAssertEqual(questionReturn, question)
        
        let factor = try TssSecurityQuestionModule.get_factor_key(threshold: threshold_key, answer: answer, tag: "special")
        
        let factor1 = try await TssSecurityQuestionModule.input_share(threshold: threshold_key, answer: answer, tag: "special")
        do {
            let factor = try await TssSecurityQuestionModule.input_share(threshold: threshold_key, answer: answer_2, tag: "special")
            XCTFail("Should be able to get factor using incorrect answer")
        } catch {}
        
        
        XCTAssertEqual(String(factor.suffix(64)), factor_key!.hex)
        
    }
}
