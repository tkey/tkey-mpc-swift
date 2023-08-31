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
    
    func test() async {
        let key_reconstruction_details = try! await threshold_key.reconstruct()
        let question = "favorite marvel character"
        let answer = "iron man"
        let answer_2 = "captain america"
        let factor_key = try? PrivateKey.generate()
        
        try? TssSecurityQuestionModule.setSecurityQuestion(threshold: threshold_key, factorKey: factor_key!.hex, question: question, answer: answer, description: "please enter password", tag: "special")
        
        let questionReturn = try? TssSecurityQuestionModule.getSecurityQuestion(threshold: threshold_key, tag: "special")
        print(questionReturn)
        XCTAssertEqual(questionReturn, question)
        
        let factor = try? TssSecurityQuestionModule.getFactorKey(threshold: threshold_key, answer: answer, tag: "special")
        
        XCTAssertEqual(String(factor!.suffix(64)), factor_key!.hex)
        
    }
}
