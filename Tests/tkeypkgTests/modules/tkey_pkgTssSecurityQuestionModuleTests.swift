import XCTest
import Foundation
@testable import tkey_pkg
import Foundation

final class tkey_pkgTssSecurityQuestionModuleTests: XCTestCase {
    private var threshold_key: ThresholdKey!
    private var storage_layer: StorageLayer!
    private var service_provider: ServiceProvider!
    
    override func setUp() async throws {
        let postbox_key = try! PrivateKey.generate()
        let storage_layer_local = try! StorageLayer(enable_logging: true, host_url: "https://metadata.tor.us", server_time_offset: 2)
        let service_provider_local = try! ServiceProvider(enable_logging: true, postbox_key: postbox_key.hex)
        let threshold = try! ThresholdKey(
            storage_layer: storage_layer_local,
            service_provider: service_provider_local,
            enable_logging: true,
            manual_sync: false
        )

        _ = try! await threshold.initialize()
        threshold_key = threshold
        service_provider = service_provider_local
        storage_layer = storage_layer_local
    }
    
    override func tearDown() {
        threshold_key = nil
    }
    
    func test() async throws {
        let key_reconstruction_details = try! await threshold_key.reconstruct()
        let question = "favorite marvel character"
        let question2 = "favorite villian character"
        let answer = "iron man"
        let answer_2 = "captain america"
        let factor_key = try? PrivateKey.generate()
        
        var allIndex = try! threshold_key.get_shares_indexes()
        allIndex.removeAll(where: {$0 == "1"})
        try! TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: allIndex[0], factorKey: factor_key!.hex)
        
        try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key,  question: question, answer: answer,factorKey: factor_key!.hex, tag: "special")
        
        
        do {
            try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key, question: question, answer: answer_2, factorKey: factor_key!.hex, tag: "special")
            XCTFail("Should not able to set quesetion twice")
        } catch {}
        
        let questionReturn = try? TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        XCTAssertEqual(questionReturn, question)
        
        let factor = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
        do {
            let factorWrong = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
            XCTFail("Should be able to get factor using incorrect answer")
        } catch {}
        try await threshold_key.input_factor_key(factorKey: factor)
        
        
        XCTAssertEqual(String(factor.suffix(64)), factor_key!.hex)
        
        
        // delete security question and add new security question
        try await TssSecurityQuestionModule.delete_security_question(threshold: threshold_key, tag: "special")
        do {
            try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
            XCTFail("Should not able get question after delete")
        }catch{}
        do {
            let factor = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
            XCTFail("Should not able get question after delete")
        }catch{}
        
        // able to set new question and answer
        try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key, question: question2, answer: answer_2, factorKey: factor_key!.hex, tag: "special")
        
        let questionReturn2 = try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        XCTAssertEqual(questionReturn2, question2)
        
        let factor2 = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
        
        do {
            let factor = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
            XCTFail("Should be able to get factor using incorrect answer")
        } catch {}
        
        XCTAssertEqual(String(factor2.suffix(64)), factor_key!.hex)
        
        // change answer and security question
        do {
            try await TssSecurityQuestionModule.change_security_question(threshold: threshold_key, newQuestion: question, newAnswer: answer, answer: answer, tag: "special")
            XCTFail("Should be not able to change sq using incorrect answer")
        } catch {}
        
        try await TssSecurityQuestionModule.change_security_question(threshold: threshold_key, newQuestion: question, newAnswer: answer, answer: answer_2, tag: "special")
        
        do {
            let factorResult = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
            XCTFail("Should be not able to get factor using incorrect answer")
        } catch {}
        
        let questionChanged = try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        let factorChanged = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
        
        XCTAssertEqual(String(factorChanged.suffix(64)), factor_key!.hex)
        XCTAssertEqual(questionChanged, question)
        
        try await threshold_key.sync_local_metadata_transistions()
        
        let newThreshold = try! ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false
        )
        
        try await newThreshold.initialize();
        
        let newInstanceQuestion = try TssSecurityQuestionModule.get_question(threshold: newThreshold, tag: "special")
        let newInstanceFactor = try TssSecurityQuestionModule.recover_factor(threshold: newThreshold, answer: answer, tag: "special")
        
        try await newThreshold.input_factor_key(factorKey: newInstanceFactor)
        
        
        XCTAssertEqual(String(newInstanceFactor.suffix(64)), factor_key!.hex)
        XCTAssertEqual(newInstanceQuestion, question)
    }
    
    func test_js_compatible () async throws {
        let threshold = try! ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false
        )
//        threshold.init
    }
}
