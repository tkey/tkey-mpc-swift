import Foundation

import Foundation
#if canImport(tkey)
    import tkey
#endif
import CommonSources
import FetchNodeDetails
import TorusUtils

public struct TSSPubKeyResult: Codable {
    public struct Point: Codable {
        public var x: String
        public var y: String

        public func toFullAddr() -> String {
            return "04" + x + y
        }
    }

    public var publicKey: Point
    public var nodeIndexes: [Int]
}

public final class TssModule {
    private static func set_tss_tag(threshold_key: ThresholdKey, tss_tag: String, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let tss_tag_pointer: UnsafeMutablePointer<Int8>? = UnsafeMutablePointer<Int8>(mutating: NSString(string: tss_tag).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_set_tss_tag(threshold_key.pointer, tss_tag_pointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey set_tss_tag")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Set the active tss tag
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tag to be set.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    static func set_tss_tag(threshold_key: ThresholdKey, tss_tag: String) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Returns the current active tss tag
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///
    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_tss_tag(threshold_key: ThresholdKey) throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tss_tag(threshold_key.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_tss_tag")
        }
        let string = String(cString: result!)
        string_free(result)
        return string
    }

    /// Get all tss tags in the metadata
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///
    /// - Returns: Array of String
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_all_tss_tags(threshold_key: ThresholdKey) throws -> [String] {
        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_all_tss_tags(threshold_key.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_tss_tag")
        }
        let string = String(cString: result!)
        string_free(result)
        guard let data = string.data(using: .utf8) else {
            throw RuntimeError("Error in get_all_tss_tag : Invalid output ")
        }
        guard let result_vec = try JSONSerialization.jsonObject(with: data) as? [String] else {
            throw RuntimeError("Error in get_all_tss_tag : Invalid output ")
        }

        return result_vec
    }

    /// Returns all factor public keys for tagged tss key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tag.
    ///
    /// - Returns: Array of String
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_all_factor_pub(threshold_key: ThresholdKey, tss_tag: String) async throws -> [String] {
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tss_tag_factor_pub(threshold_key.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_all_factor_pub")
        }
        let string = String(cString: result!)
        string_free(result)
        guard let data = string.data(using: .utf8) else {
            throw RuntimeError("Error in get_all_factor_pub : Invalid output ")
        }
        guard let result_vec = try JSONSerialization.jsonObject(with: data) as? [String] else {
            throw RuntimeError("Error in get_all_factor_pub : Invalid output ")
        }

        return result_vec
    }

    /// Returns the tagged final tss public key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tag
    ///
    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_tss_pub_key(threshold_key: ThresholdKey, tss_tag: String) async throws -> String {
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tss_public_key(threshold_key.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_tss_tag")
        }
        let string = String(cString: result!)
        string_free(result)
        return string
    }

    /// Returns the tagged tss nonce
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tag.
    ///   - prefetch: Fetch the next nonce's pub key
    ///
    /// - Returns: `Int32`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_tss_nonce(threshold_key: ThresholdKey, tss_tag: String, prefetch: Bool = false) throws -> Int32 {
        var errorCode: Int32 = -1
        let tss_tag_pointer: UnsafeMutablePointer<Int8>? = UnsafeMutablePointer<Int8>(mutating: NSString(string: tss_tag).utf8String)
        var nonce = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tss_nonce(threshold_key.pointer, tss_tag_pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_tss_nonce")
        }

        if prefetch {
            nonce += 1
        }

        return nonce
    }

    /// Returns latest tss index and tss share registed to the factor key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tag.
    ///   - factorKey: Public key of the new factor that was previously added
    ///   - threshold: The threshold
    ///
    /// - Returns: `(String, String)`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_tss_share(threshold_key: ThresholdKey, tss_tag: String, factorKey: String, threshold: Int32 = 0) async throws -> (String, String) {
        if factorKey.count > 66 { throw RuntimeError("Invalid factor Key") }
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        var errorCode: Int32 = -1

        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
        let factorKeyPointer = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tss_share(threshold_key.pointer, factorKeyPointer, threshold, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_tss_share")
        }
        let string = String(cString: result!)
        string_free(result)
        let splitString = string.split(separator: ",", maxSplits: 2)
        return (String(splitString[0]), String(splitString[1]))
    }

    private static func create_tagged_tss_share(threshold_key: ThresholdKey, deviceTssShare: String?, factorPub: String, deviceTssIndex: Int32, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                var errorCode: Int32 = -1

                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
                var deviceTssSharePointer: UnsafeMutablePointer<Int8>?
                if let deviceTssShare = deviceTssShare {
                    deviceTssSharePointer = UnsafeMutablePointer<Int8>(mutating: (deviceTssShare as NSString).utf8String)
                }
                let factorPubPointer = UnsafeMutablePointer<Int8>(mutating: (factorPub as NSString).utf8String)

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_create_tagged_tss_share(threshold_key.pointer, deviceTssSharePointer, factorPubPointer, deviceTssIndex, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey create_tagged_tss_share")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Initialize new tagged tss key and create the tss share
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: tss key's tag.
    ///   - deviceTssShare : specific value that will be tss share of the final tss key, optional. *note: after tss refresh (add factor pub or delete factor pub) current tss share will be invalidated*
    ///   - factorPub: public key of the new factor that added (registered)
    ///   - deviceTssIndex: Tss Index of tss share should be associated
    ///   - nodeDetails: nodeDetails that sdk should comunicate to
    ///   - torusUtils: torusUtils used to retrieve dkg tss pub key
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func create_tagged_tss_share(threshold_key: ThresholdKey, tss_tag: String, deviceTssShare: String?, factorPub: String, deviceTssIndex: Int32, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils) async throws {
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)
        try await TssModule.update_tss_pub_key(threshold_key: threshold_key, tss_tag: tss_tag, nodeDetails: nodeDetails, torusUtils: torusUtils)
        return try await withCheckedThrowingContinuation {
            continuation in
            create_tagged_tss_share(threshold_key: threshold_key, deviceTssShare: deviceTssShare, factorPub: factorPub, deviceTssIndex: deviceTssIndex) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func update_tss_pub_key(threshold_key: ThresholdKey, tss_tag: String, nonce: String, public_key: String, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                try threshold_key.service_provider_assign_public_key(tag: tss_tag, nonce: nonce, public_key: public_key)
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    ///  Get and update latest dkg tss_pub_key with latest nonce
    /// - Parameters:
    ///    - threshold_key: The threshold key to act on
    ///    - tss_tag: The tss tag.
    ///    - nodeDetails: nodeDetails that sdk should comunicate to
    ///    - torusUtils: torusUtils used to retrieve dkg tss pub key
    ///    - prefetch: Fetch the next nonce's pub key
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func update_tss_pub_key(threshold_key: ThresholdKey, tss_tag: String, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils, prefetch: Bool = false) async throws {
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        let nonce = String(try get_tss_nonce(threshold_key: threshold_key, tss_tag: tss_tag, prefetch: prefetch))

        let public_address = try await get_dkg_pub_key(threshold_key: threshold_key, tssTag: tss_tag, nonce: nonce, nodeDetails: nodeDetails, torusUtils: torusUtils)
        let pk_encoded = try JSONEncoder().encode(public_address)
        guard let public_key = String(data: pk_encoded, encoding: .utf8) else {
            throw RuntimeError("update_tss_pub_key - Conversion Error - ResultString")
        }

        return try await withCheckedThrowingContinuation {
            continuation in
            update_tss_pub_key(threshold_key: threshold_key, tss_tag: tss_tag, nonce: nonce, public_key: public_key) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func copy_factor_pub(threshold_key: ThresholdKey, factorKey: String, newFactorPub: String, tss_index: Int32, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                var errorCode: Int32 = -1

                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
                let factorKeyPointer = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)
                let newFactorPubPointer = UnsafeMutablePointer<Int8>(mutating: (newFactorPub as NSString).utf8String)

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_copy_factor_pub(threshold_key.pointer, newFactorPubPointer, tss_index, factorKeyPointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey copy_factor_pub")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Copy tss share from existing factor to new factor key (register)
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: The tss tah.
    ///   - factor_key: Valid factor key that needed to execute this operation.
    ///   - auth_signatures: Signature data that need to be validated by signing server .
    ///   - new_factor_pub: Public key of the new factor that added (registered)
    ///   - tss_index: tss_index that should match with existing factor key's tss_index
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func copy_factor_pub(threshold_key: ThresholdKey, tss_tag: String, factorKey: String, newFactorPub: String, tss_index: Int32) async throws {
        if factorKey.count > 66 { throw RuntimeError("Invalid factor Key") }
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        return try await withCheckedThrowingContinuation {
            continuation in
            copy_factor_pub(threshold_key: threshold_key, factorKey: factorKey, newFactorPub: newFactorPub, tss_index: tss_index) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func generate_tss_share(threshold_key: ThresholdKey, input_tss_share: String, tss_input_index: Int32, auth_signatures: [String], new_factor_pub: String, new_tss_index: Int32, selected_servers: [Int32]? = nil, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)

                let auth_signatures_json = try JSONSerialization.data(withJSONObject: auth_signatures)
                guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
                    throw RuntimeError("auth signatures error")
                }
                let inputSharePointer = UnsafeMutablePointer<Int8>(mutating: (input_tss_share as NSString).utf8String)
                let newFactorPubPointer = UnsafeMutablePointer<Int8>(mutating: (new_factor_pub as NSString).utf8String)

                let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)

                var serversPointer: UnsafeMutablePointer<Int8>?
                if selected_servers != nil {
                    let selected_servers_json = try JSONSerialization.data(withJSONObject: selected_servers as Any)
                    let selected_servers_str = String(data: selected_servers_json, encoding: .utf8)!
                    serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)
                }

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_generate_tss_share(threshold_key.pointer, inputSharePointer, tss_input_index, new_tss_index, newFactorPubPointer, serversPointer, authSignaturesPointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey generate_tss_share")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    public static func generate_tss_share(threshold_key: ThresholdKey, tss_tag: String, input_tss_share: String, tss_input_index: Int32, auth_signatures: [String], new_factor_pub: String, new_tss_index: Int32, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils, selected_servers: [Int32]? = nil) async throws {
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        try await update_tss_pub_key(threshold_key: threshold_key, tss_tag: tss_tag, nodeDetails: nodeDetails, torusUtils: torusUtils, prefetch: true)

        return try await withCheckedThrowingContinuation {
            continuation in
            generate_tss_share(threshold_key: threshold_key, input_tss_share: input_tss_share, tss_input_index: tss_input_index, auth_signatures: auth_signatures, new_factor_pub: new_factor_pub, new_tss_index: new_tss_index) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    private static func delete_tss_share(threshold_key: ThresholdKey, input_tss_share: String, tss_input_index: Int32, auth_signatures: [String], delete_factor_pub: String, selected_servers: [Int32]? = nil, completion: @escaping (Result<Void, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)

                let auth_signatures_json = try JSONSerialization.data(withJSONObject: auth_signatures)
                guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
                    throw RuntimeError("auth signatures error")
                }
                let inputSharePointer = UnsafeMutablePointer<Int8>(mutating: (input_tss_share as NSString).utf8String)
                let factorPubPointer = UnsafeMutablePointer<Int8>(mutating: (delete_factor_pub as NSString).utf8String)

                let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)

                var serversPointer: UnsafeMutablePointer<Int8>?
                if selected_servers != nil {
                    let selected_servers_json = try JSONSerialization.data(withJSONObject: selected_servers as Any)
                    let selected_servers_str = String(data: selected_servers_json, encoding: .utf8)!
                    serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)
                }

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_delete_tss_share(threshold_key.pointer, inputSharePointer, tss_input_index, factorPubPointer, serversPointer, authSignaturesPointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey delete tss share")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    public static func delete_tss_share(threshold_key: ThresholdKey, tss_tag: String, input_tss_share: String, tss_input_index: Int32, auth_signatures: [String], delete_factor_pub: String, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils, selected_servers: [Int32]? = nil) async throws {
        try await update_tss_pub_key(threshold_key: threshold_key, tss_tag: tss_tag, nodeDetails: nodeDetails, torusUtils: torusUtils, prefetch: true)
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        return try await withCheckedThrowingContinuation {
            continuation in
            delete_tss_share(threshold_key: threshold_key, input_tss_share: input_tss_share, tss_input_index: tss_input_index, auth_signatures: auth_signatures, delete_factor_pub: delete_factor_pub) {
                result in
                switch result {
                case let .success(result):
                    continuation.resume(returning: result)
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Generate tss_index's share and register to new factor key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: tss key's tag.
    ///   - factor_key: valid factor key that needed to execute this operation.
    ///   - auth_signatures: signature data that need to be validated by signing server .
    ///   - new_factor_pub: public key of the new factor that added (registered)
    ///   - new_tss_index: tss_index of the new tss share (to be registered)
    ///   - selected_servers: node indexes of the server that will be communicated to
    ///   - nodeDetails: node details
    ///   - torusUtils: torus utils
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func add_factor_pub(threshold_key: ThresholdKey, tss_tag: String, factor_key: String, auth_signatures: [String], new_factor_pub: String, new_tss_index: Int32, selected_servers: [Int32]? = nil, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils) async throws {
        if factor_key.count > 66 { throw RuntimeError("Invalid factor Key") }
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        let (tss_index, tss_share) = try await get_tss_share(threshold_key: threshold_key, tss_tag: tss_tag, factorKey: factor_key)
        try await TssModule.generate_tss_share(threshold_key: threshold_key, tss_tag: tss_tag, input_tss_share: tss_share, tss_input_index: Int32(tss_index)!, auth_signatures: auth_signatures, new_factor_pub: new_factor_pub, new_tss_index: new_tss_index, nodeDetails: nodeDetails, torusUtils: torusUtils, selected_servers: selected_servers)
    }

    /// Delete factor pub from tss metadata
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tss_tag: tss key's tag.
    ///   - factor_key: valid factor key that needed to execute this operation.
    ///   - auth_signatures: signature data that need to be validated by signing server .
    ///   - delete_factor_pub: public key of the factor that need to be deleted.
    ///   - nodeDetails: node details
    ///   - torusUtils: torus utils
    ///   - selected_servers: node indexes of the server that will be communicated to
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func delete_factor_pub(threshold_key: ThresholdKey, tss_tag: String, factor_key: String, auth_signatures: [String], delete_factor_pub: String, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils, selected_servers: [Int32]? = nil) async throws {
        if factor_key.count > 66 { throw RuntimeError("Invalid factor Key") }
        try await TssModule.set_tss_tag(threshold_key: threshold_key, tss_tag: tss_tag)

        let (tss_index, tss_share) = try await get_tss_share(threshold_key: threshold_key, tss_tag: tss_tag, factorKey: factor_key)
        try await TssModule.delete_tss_share(threshold_key: threshold_key, tss_tag: tss_tag, input_tss_share: tss_share, tss_input_index: Int32(tss_index)!, auth_signatures: auth_signatures, delete_factor_pub: delete_factor_pub, nodeDetails: nodeDetails, torusUtils: torusUtils, selected_servers: selected_servers)
    }

    /// Backup device share with factor key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - shareIndex: Index of the Share to be backed up.
    ///   - factorKey: factor key to be used for backup.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func backup_share_with_factor_key(threshold_key: ThresholdKey, shareIndex: String, factorKey: String) throws {
        var errorCode: Int32 = -1

        let cShareIndex = UnsafeMutablePointer<Int8>(mutating: (shareIndex as NSString).utf8String)
        let cFactorKey = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)

        withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_backup_share_with_factor_key(threshold_key.pointer, cShareIndex, cFactorKey, curvePointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey backup_share_with_factor_key")
        }
    }

    /// Find the metadata share Index registred with factor_key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - factor_key: factor key to be used.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func find_device_share_index(threshold_key: ThresholdKey, factor_key: String) async throws -> String {
        let result = try await threshold_key.storage_layer_get_metadata(private_key: factor_key)
        guard let resultData = result.data(using: .utf8) else {
            throw "Invalid factor key"
        }
        guard let resultJson = try JSONSerialization.jsonObject(with: resultData) as? [String: Any] else {
            throw "Invalid factor key"
        }
        
        var deviceShareJson = resultJson;
        
        // backward competible
        if resultJson["deviceShare"] != nil {
            guard let deviceShare = resultJson["deviceShare"] as? [String: Any] else {
                throw "Invalid factor key"
            }
            deviceShareJson = deviceShare
        }

        guard let shareJson = deviceShareJson["share"] as? [String: Any] else {
            throw "Invalid factor key"
        }
        guard let shareIndex = shareJson["shareIndex"] as? String else {
            throw "Invalid factor key"
        }
        return shareIndex
    }

    /// Function to get dkg public key
    /// - Parameters:
    ///   - threshold_key: The threshold key to act on.
    ///   - tssTag: tssTag used.
    ///   - nonce: nonce
    ///   - nodeDetails: node details
    ///   - torusUtils: torus utils
    /// - Returns: `TSSPubKeyResult`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters was used or invalid threshold key.
    public static func get_dkg_pub_key(threshold_key: ThresholdKey, tssTag: String, nonce: String, nodeDetails: AllNodeDetailsModel, torusUtils: TorusUtils) async throws -> TSSPubKeyResult {
        let extendedVerifierId = try threshold_key.get_extended_verifier_id()
        let split = extendedVerifierId.components(separatedBy: "\u{001c}")

        let result = try await torusUtils.getPublicAddress(endpoints: nodeDetails.torusNodeEndpoints, torusNodePubs: nodeDetails.torusNodePub, verifier: split[0], verifierId: split[1], extendedVerifierId: "\(split[1])\u{0015}\(tssTag)\u{0016}\(nonce)")

        guard let x = result.finalKeyData?.X, let y = result.finalKeyData?.Y, let nodeIndexes = result.nodesData?.nodeIndexes else {
            throw RuntimeError("conversion error")
        }
        let pubKey = TSSPubKeyResult.Point(x: x, y: y)
        return TSSPubKeyResult(publicKey: pubKey, nodeIndexes: nodeIndexes.sorted())
    }
}
