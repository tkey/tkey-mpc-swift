import XCTest
import Foundation
@testable import tkey_pkg
import Foundation
import TorusUtils
import CommonSources
import FetchNodeDetails

final class tkey_pkgTssSecurityQuestionModuleTests: XCTestCase {
    private var threshold_key: ThresholdKey!
    private var storage_layer: StorageLayer!
    private var service_provider: ServiceProvider!
    
    override func setUp() async throws {
        let TORUS_TEST_EMAIL = "saasa2123@tr.us"
        let TORUS_TEST_VERIFIER = "torus-test-health"

        let nodeManager = NodeDetailManager(network: .sapphire(.SAPPHIRE_DEVNET))
        let nodeDetail = try await nodeManager.getNodeDetails(verifier: TORUS_TEST_VERIFIER, verifierID: TORUS_TEST_EMAIL)
        let torusUtils = TorusUtils(serverTimeOffset: 1000, network: .sapphire(.SAPPHIRE_DEVNET))

        let idToken = try generateIdToken(email: TORUS_TEST_EMAIL)
        let verifierParams = VerifierParams(verifier_id: TORUS_TEST_EMAIL)
        let retrievedShare = try await torusUtils.retrieveShares(endpoints: nodeDetail.torusNodeEndpoints, torusNodePubs: nodeDetail.torusNodePub, indexes: nodeDetail.torusIndexes, verifier: TORUS_TEST_VERIFIER, verifierParams: verifierParams, idToken: idToken)
        let signature = retrievedShare.sessionData?.sessionTokenData
        let signatures = signature!.compactMap { item in
            item?.signature
        }
        
        
        let postbox_key = try! PrivateKey.generate()
        let tssEndpoint0 = nodeDetail.torusNodeTSSEndpoints[0]
        let metadataEndpoint = tssEndpoint0.replacingOccurrences(of: "/tss", with: "") + "/metadata"
        let storage_layer_local = try! StorageLayer(enable_logging: true, host_url: metadataEndpoint, server_time_offset: 2)
        let service_provider_local = try! ServiceProvider(enable_logging: true, postbox_key: postbox_key.hex, verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL, nodeDetails: nodeDetail)
        let rss_comm = try! RssComm()
        let threshold = try! ThresholdKey(
            storage_layer: storage_layer_local,
            service_provider: service_provider_local,
            enable_logging: true,
            manual_sync: false,
            rss_comm: rss_comm
        )

        _ = try! await threshold.initialize()
        
        // setting variables needed for tss operations
        threshold.setAuthSignatures(authSignatures: signatures)
        threshold.setnodeDetails(nodeDetails: nodeDetail)
        threshold.setTorusUtils(torusUtils: torusUtils)
        
        threshold_key = threshold
        service_provider = service_provider_local
        storage_layer = storage_layer_local
    }
    
    override func tearDown() {
        threshold_key = nil
    }
    
    func test() async throws {
        let _ = try! await threshold_key.reconstruct()
        let question = "favorite marvel character"
        let question2 = "favorite villian character"
        let answer = "iron man"
        let answer_2 = "captain america"
        let factor_key = try! PrivateKey.generate()
        let factor_pub = try factor_key.toPublic(format: .EllipticCompress)
        var allIndex = try! threshold_key.get_shares_indexes()
        allIndex.removeAll(where: {$0 == "1"})
        
        try await TssModule.create_tagged_tss_share(threshold_key: threshold_key, tss_tag: "special", deviceTssShare: nil, factorPub: factor_pub, deviceTssIndex: 2)
        
        try! TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: allIndex[0], factorKey: factor_key.hex)
        
        let sq_factor = try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key,  question: question, answer: answer,factorKey: factor_key.hex, tag: "special")
        
        
        do {
            let _ = try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key, question: question, answer: answer_2, factorKey: factor_key.hex, tag: "special")
            XCTFail("Should not able to set quesetion twice")
        } catch {}
        
        let questionReturn = try? TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        XCTAssertEqual(questionReturn, question)
        
        let factor = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
        do {
            let _ = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
            XCTFail("Should be able to get factor using incorrect answer")
        } catch {}
        try await threshold_key.input_factor_key(factorKey: factor)
        // check for valid tss share
        let _ = try await TssModule.get_tss_share(threshold_key: threshold_key, tss_tag: "special", factorKey: factor)
        
        XCTAssertEqual(String(factor.suffix(64)), sq_factor)
        
        // delete security question and add new security question
        let factorPubDeleted = try await TssSecurityQuestionModule.delete_security_question(threshold: threshold_key, tag: "special", factorKey: factor_key.hex)
        XCTAssertEqual(factorPubDeleted, try PrivateKey(hex: sq_factor).toPublic(format: .EllipticCompress))
    
        
        do {
            let _ = try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
            XCTFail("Should not able get question after delete")
        }catch{}
        do {
            let _ = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
            XCTFail("Should not able get question after delete")
        }catch{}
        
        // able to set new question and answer
        let sq_factor2 = try await TssSecurityQuestionModule.set_security_question(threshold: threshold_key, question: question2, answer: answer_2, factorKey: factor_key.hex, tag: "special")
        
        let questionReturn2 = try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        XCTAssertEqual(questionReturn2, question2)
        
        let factor2 = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
        
        do {
            let _ = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
            XCTFail("Should be able to get factor using incorrect answer")
        } catch {}
        
        XCTAssertEqual(String(factor2.suffix(64)), sq_factor2)
        
        // change answer and security question
        do {
            let _ = try await TssSecurityQuestionModule.change_security_question(threshold: threshold_key, newQuestion: question, newAnswer: answer, answer: answer, tag: "special")
            XCTFail("Should be not able to change sq using incorrect answer")
        } catch {}
        
        let (old_sq_factor, new_sq_factor) = try await TssSecurityQuestionModule.change_security_question(threshold: threshold_key, newQuestion: question, newAnswer: answer, answer: answer_2, tag: "special")
        
        XCTAssertEqual(old_sq_factor, sq_factor2)
        
        do {
            let _ = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer_2, tag: "special")
            XCTFail("Should be not able to get factor using incorrect answer")
        } catch {}
        
        let questionChanged = try TssSecurityQuestionModule.get_question(threshold: threshold_key, tag: "special")
        let factorChanged = try TssSecurityQuestionModule.recover_factor(threshold: threshold_key, answer: answer, tag: "special")
        
        XCTAssertEqual(String(factorChanged.suffix(64)), new_sq_factor)
        XCTAssertEqual(questionChanged, question)
        
        try await threshold_key.sync_local_metadata_transistions()
        
        let newThreshold = try! ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false
        )
        
        let _ = try await newThreshold.initialize();
        
        let newInstanceQuestion = try TssSecurityQuestionModule.get_question(threshold: newThreshold, tag: "special")
        let newInstanceFactor = try TssSecurityQuestionModule.recover_factor(threshold: newThreshold, answer: answer, tag: "special")
        
        try await newThreshold.input_factor_key(factorKey: newInstanceFactor)
        try await newThreshold.input_factor_key(factorKey: newInstanceFactor)
        let _ = try await newThreshold.reconstruct()
        
        XCTAssertEqual(String(newInstanceFactor.suffix(64)), new_sq_factor)
        XCTAssertEqual(newInstanceQuestion, question)
    }
    
    func test_js_compatible () async throws {
        
        let TORUS_TEST_EMAIL = "testing2001@example.com"
        let TORUS_TEST_VERIFIER = "torus-test-health"
        
        let nodeManager = NodeDetailManager(network: .sapphire(.SAPPHIRE_DEVNET))
        let nodeDetail = try await nodeManager.getNodeDetails(verifier: TORUS_TEST_VERIFIER, verifierID: TORUS_TEST_EMAIL)
        let torusUtils = TorusUtils(serverTimeOffset: 2, network: .sapphire(.SAPPHIRE_DEVNET))
        
        let idToken = try generateIdToken(email: TORUS_TEST_EMAIL)
        let verifierParams = VerifierParams(verifier_id: TORUS_TEST_EMAIL)
        let retrievedShare = try await torusUtils.retrieveShares(endpoints: nodeDetail.torusNodeEndpoints, torusNodePubs: nodeDetail.torusNodePub, indexes: nodeDetail.torusIndexes, verifier: TORUS_TEST_VERIFIER, verifierParams: verifierParams, idToken: idToken)
        let signature = retrievedShare.sessionData?.sessionTokenData
        let signatures = signature!.compactMap { item in
            item?.signature
        }
        
        guard let postbox = retrievedShare.oAuthKeyData?.privKey else {
            throw "invalid postbox key"
        }
        print(postbox)
        let service_provider_local = try! ServiceProvider(enable_logging: true, postbox_key: postbox , verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL, nodeDetails: nodeDetail)
        let rss_comm = try  RssComm()
        let threshold = try! ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider_local,
            enable_logging: true,
            manual_sync: false,
            rss_comm: rss_comm
        )

        _ = try! await threshold.initialize()
        
        // setting variables needed for tss operations
        threshold.setAuthSignatures(authSignatures: signatures)
        threshold.setnodeDetails(nodeDetails: nodeDetail)
        threshold.setTorusUtils(torusUtils: torusUtils)
//        threshold.init
        print( try threshold.get_key_details().pub_key.getPublicKey(format: .EllipticCompress))
        let factorKey = "36c1728c47c84dfe855949fa76daf82f8bda801af9374f30aa4c91b7fd7a8e3b"
        let answer = "jsanswer"
        let question = "js question"
        
        let questionResult = try TssSecurityQuestionModule.get_question(threshold: threshold, tag: "default")
        print(questionResult)
        let factor = try TssSecurityQuestionModule.recover_factor(threshold: threshold, answer: answer, tag: "default")
        print(factor)
        
        try await threshold.input_factor_key(factorKey: factor)
        try await threshold.reconstruct()
        let (tssIndex, tssShare) = try await TssModule.get_tss_share(threshold_key: threshold, tss_tag: "default", factorKey: factor)
        print (tssIndex)
        print (tssShare)
    }
}
