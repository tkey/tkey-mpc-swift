import Foundation
#if canImport(lib)
    import lib
#endif
import CommonSources
import TorusUtils

public class ThresholdKey {
    private(set) var pointer: OpaquePointer?
    private(set) var use_tss: Bool = false
    internal let curveN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    internal let tkeyQueue = DispatchQueue(label: "thresholdkey.queue")
    internal var authSignatures: [String]?
    internal var nodeDetails: AllNodeDetailsModel?
    internal var torusUtils: TorusUtils?
    
    public func getAuthSignatures () throws -> [String] {
        guard let result = self.authSignatures else {
            throw "authSignatures is undefined"
        }
        return result
    }
    public func getnodeDetails () throws -> AllNodeDetailsModel {
        guard let result = self.nodeDetails else {
            throw "authSignatures is undefined"
        }
        return result
    }
    public func getTorusUtils () throws -> TorusUtils {
        guard let result = self.torusUtils else {
            throw "authSignatures is undefined"
        }
        return result
    }
    
    public func setAuthSignatures ( authSignatures: [String]) {
        self.authSignatures = authSignatures
    }
    public func setnodeDetails (nodeDetails : AllNodeDetailsModel) {
        self.nodeDetails = nodeDetails
    }
    public func setTorusUtils (torusUtils : TorusUtils) {
        self.torusUtils = torusUtils
    }

    
    /// Instantiate a `ThresholdKey` object,
    ///
    /// - Parameters:
    ///   - metadata: Existing metadata to be used, optional.
    ///   - shares: Existing shares to be used, optional.
    ///   - storage_layer: Storage layer to be used.
    ///   - service_provider: Service provider to be used, optional only in the most basic usage of tKey.
    ///   - local_matadata_transitions: Existing local transitions to be used.
    ///   - last_fetch_cloud_metadata: Existing cloud metadata to be used.
    ///   - enable_logging: Determines whether logging is available or not (pending).
    ///   - manual_sync: Determines if changes to the metadata are automatically synced.
    ///   - rss_comm: RSS client, required for TSS.
    ///
    /// - Returns: `ThresholdKey`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters.
    public init(metadata: Metadata? = nil, shares: ShareStorePolyIdIndexMap? = nil, storage_layer: StorageLayer, service_provider: ServiceProvider? = nil, local_matadata_transitions: LocalMetadataTransitions? = nil, last_fetch_cloud_metadata: Metadata? = nil, enable_logging: Bool, manual_sync: Bool, rss_comm: RssComm? = nil) throws {
        var errorCode: Int32 = -1
        var providerPointer: OpaquePointer?
        if case let .some(provider) = service_provider {
            providerPointer = provider.pointer
        }

        var sharesPointer: OpaquePointer?
        var metadataPointer: OpaquePointer?
        var cloudMetadataPointer: OpaquePointer?
        var transitionsPointer: OpaquePointer?
        var rssCommPtr: OpaquePointer?
        if shares != nil {
            sharesPointer = shares!.pointer
        }

        if metadata != nil {
            metadataPointer = metadata!.pointer
        }

        if last_fetch_cloud_metadata != nil {
            cloudMetadataPointer = last_fetch_cloud_metadata!.pointer
        }

        if local_matadata_transitions != nil {
            transitionsPointer = local_matadata_transitions!.pointer
        }

        if rss_comm != nil {
            rssCommPtr = rss_comm!.pointer
            use_tss = true
        }

        let result = withUnsafeMutablePointer(to: &errorCode, { error -> OpaquePointer in
            threshold_key(metadataPointer, sharesPointer, storage_layer.pointer, providerPointer, transitionsPointer, cloudMetadataPointer, enable_logging, manual_sync, rssCommPtr, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey")
        }

        pointer = result
    }

    /// Returns the metadata,
    ///
    /// - Returns: `Metadata`
    ///
    /// - Throws: `RuntimeError`, indicates invalid underlying poiner.
    public func get_metadata() throws -> Metadata {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_get_current_metadata(pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_metadata")
        }
        return Metadata(pointer: result!)
    }

    private func initialize(import_metdata_key: String?, input: ShareStore?, never_initialize_new_key: Bool?, include_local_metadata_transitions: Bool?, completion: @escaping (Result<KeyDetails, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                var keyPointer: UnsafeMutablePointer<Int8>?
                var device_index: Int32 = 2
                let useTss = false
                
                if import_metdata_key != nil {
                    keyPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: import_metdata_key!).utf8String)
                }

                var storePtr: OpaquePointer?
                if input != nil {
                    storePtr = input!.pointer
                }

                let neverInitializeNewKey = never_initialize_new_key ?? false
                let includeLocalMetadataTransitions = include_local_metadata_transitions ?? false

                let curvePointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: self.curveN).utf8String)
                let ptr = withUnsafeMutablePointer(to: &device_index, { tssDeviceIndexPointer in withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_initialize(self.pointer, keyPointer, storePtr, neverInitializeNewKey, includeLocalMetadataTransitions, false,  curvePointer, useTss, nil, tssDeviceIndexPointer, nil, error) }) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey Initialize \(errorCode)")
                }
                let result = try! KeyDetails(pointer: ptr!)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Initializes a `ThresholdKey` object.
    ///
    /// - Parameters:
    ///   - import_metdata_key: Metadata key to be imported, optional.
    ///   - input: `ShareStore` to be used, optional.
    ///   - never_initialize_new_key: Do not initialize a new tKey if an existing one is found.
    ///   - include_local_matadata_transitions: Proritize existing metadata transitions over cloud fetched transitions.
    ///
    /// - Returns: `KeyDetails`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters.
    public func initialize(import_metdata_key: String? = nil, input: ShareStore? = nil, never_initialize_new_key: Bool? = nil, include_local_metadata_transitions: Bool? = nil ) async throws -> KeyDetails {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.initialize(import_metdata_key: import_metdata_key, input: input, never_initialize_new_key: never_initialize_new_key, include_local_metadata_transitions: include_local_metadata_transitions ) {
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

    private func reconstruct(completion: @escaping (Result<KeyReconstructionDetails, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let ptr = withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_reconstruct(self.pointer, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey Reconstruct")
                }
                let result = try! KeyReconstructionDetails(pointer: ptr!)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Reconstructs the private key, this assumes that the number of shares inserted into the `ThresholdKey` are equal or greater than the threshold.
    ///
    /// - Returns: `KeyReconstructionDetails`
    ///
    /// - Throws: `RuntimeError`.
    public func reconstruct() async throws -> KeyReconstructionDetails {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.reconstruct {
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

    /// Returns the latest polynomial.
    ///
    /// - Returns: `Polynomial`
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func reconstruct_latest_poly() throws -> Polynomial {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_reconstruct_latest_poly(pointer, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey reconstruct_latest_poly")
        }
        return Polynomial(pointer: result!)
    }

    /// Returns share stores for the latest polynomial.
    ///
    /// - Returns: `ShareStoreArray`
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func get_all_share_stores_for_latest_polynomial() throws -> ShareStoreArray {
        var errorCode: Int32 = -1

        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_all_share_stores_for_latest_polynomial(pointer, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_all_share_stores_for_latest_polynomial")
        }
        return ShareStoreArray(pointer: result!)
    }

    private func generate_new_share(completion: @escaping (Result<GenerateShareStoreResult, Error>) -> Void) {
        tkeyQueue.async {
            do {
                let useTss = false

                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let ptr = withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_generate_share(self.pointer, curvePointer, useTss, nil, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey generate_new_share")
                }

                let result = try GenerateShareStoreResult(pointer: ptr!)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Generates a new share.
    ///
    /// - Returns: `GenerateShareStoreResult`
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func generate_new_share() async throws -> GenerateShareStoreResult {
        return try await withCheckedThrowingContinuation {
            continuation in self.generate_new_share() {
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

    private func delete_share(share_index: String, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let shareIndexPointer = UnsafeMutablePointer<Int8>(mutating: (share_index as NSString).utf8String)

                let useTss = false

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_delete_share(self.pointer, shareIndexPointer, curvePointer, useTss, nil, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in Threshold while Deleting share")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Deletes a share at the specified index. Caution is advised to not try delete a share that would prevent the total number of shares being below the threshold.
    /// - Parameters:
    ///   - share_index: Share index to be deleted.
    /// - Throws: `RuntimeError`, indicates invalid share index or invalid `ThresholdKey`.
    public func delete_share(share_index: String) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.delete_share(share_index: share_index) {
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

    private func CRITICAL_delete_tkey(completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_delete_tkey(self.pointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in Threshold while Deleting tKey")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Permanently deletes a tKey, this process is irrecoverable.
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func CRITICAL_delete_tkey() async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.CRITICAL_delete_tkey {
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

    /// Returns the key details, mainly used after reconstruction.
    ///
    /// - Returns: `KeyDetails`
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func get_key_details() throws -> KeyDetails {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_key_details(pointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in Threshold while Getting Key Details")
        }
        return try! KeyDetails(pointer: result!)
    }

    /// Retrieves a specific share.
    ///
    /// - Parameters:
    ///   - shareIndex: The index of the share to output.
    ///   - shareType: The format of the output, can be `"mnemonic"`, optional.

    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func output_share(shareIndex: String, shareType: String? = nil) throws -> String {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let cShareIndex = UnsafeMutablePointer<Int8>(mutating: (shareIndex as NSString).utf8String)

        var cShareType: UnsafeMutablePointer<Int8>?
        if shareType != nil {
            cShareType = UnsafeMutablePointer<Int8>(mutating: (shareType! as NSString).utf8String)
        }
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_output_share(pointer, cShareIndex, cShareType, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey output_share")
        }

        let string = String(cString: result!)
        string_free(result)
        return string
    }

    /// Converts a share to a `ShareStore`.
    ///
    /// - Parameters:
    ///   - share: Hexadecimal representation of a share as `String`.

    /// - Returns: `ShareStore`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameter.
    public func share_to_share_store(share: String) throws -> ShareStore {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let sharePointer = UnsafeMutablePointer<Int8>(mutating: (share as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_share_to_share_store(pointer, sharePointer, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey share_to_share_store")
        }
        return ShareStore(pointer: result!)
    }

    private func input_share(share: String, shareType: String?, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let cShare = UnsafeMutablePointer<Int8>(mutating: (share as NSString).utf8String)

                var cShareType: UnsafeMutablePointer<Int8>?
                if shareType != nil {
                    cShareType = UnsafeMutablePointer<Int8>(mutating: (shareType! as NSString).utf8String)
                }
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_input_share(self.pointer, cShare, cShareType, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey input share")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    /// Inserts a share into `ThresholdKey`, this is used prior to reconstruction in order to ensure the number of shares meet the threshold.
    ///
    /// - Parameters:
    ///   - share: Hex representation of a share as `String`.
    ///   - shareType: The format of the share, can be `"mnemonic"`, optional.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameter of invalid `ThresholdKey`.
    public func input_share(share: String, shareType: String?) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.input_share(share: share, shareType: shareType) {
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

    /// Retrieves a specific `ShareStore`.
    ///
    /// - Parameters:
    ///   - shareIndex: The index of the share to output.
    ///   - polyID: The polynomial id to be used for the output, optional

    /// - Returns: `ShareStore`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func output_share_store(shareIndex: String, polyId: String?) throws -> ShareStore {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let cShareIndex = UnsafeMutablePointer<Int8>(mutating: (shareIndex as NSString).utf8String)

        var cPolyId: UnsafeMutablePointer<Int8>?
        if let polyId = polyId {
            cPolyId = UnsafeMutablePointer<Int8>(mutating: (polyId as NSString).utf8String)
        }
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_output_share_store(pointer, cShareIndex, cPolyId, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey output share store")
        }
        return ShareStore(pointer: result!)
    }

    private func input_share_store(shareStore: ShareStore, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_input_share_store(self.pointer, shareStore.pointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey input share store")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Inserts a `ShareStore` into `ThresholdKey`, useful for insertion before reconstruction to ensure the number of shares meet the minimum threshold.
    ///
    /// - Parameters:
    ///   - shareStore: The `ShareStore` to be inserted
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func input_share_store(shareStore: ShareStore) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.input_share_store(shareStore: shareStore) {
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
    
    private func input_factor_key(factorKey: String, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let cFactorKey = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_input_factor_key(self.pointer, cFactorKey, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey input_factor_key \(errorCode)")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Inserts a `ShareStore` into `ThresholdKey` using `FactorKey`, useful for insertion before reconstruction to ensure the number of shares meet the minimum threshold.
    ///
    /// - Parameters:
    ///   - factorKey  : The `factorKey` to be inserted
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func input_factor_key(factorKey: String) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.input_factor_key(factorKey: factorKey) {
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
    
    
//    private func patch_input_factor_key(factorKey: String, completion: @escaping (Result<Void, Error>) -> Void) {
//        tkeyQueue.async {
//            do {
//                var errorCode: Int32 = -1
//                let cFactorKey = UnsafeMutablePointer<Int8>(mutating: (factorKey as NSString).utf8String)
//                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
//
//                withUnsafeMutablePointer(to: &errorCode, { error in
//                    threshold_key_patch_input_factor_key(self.pointer, cFactorKey, curvePointer, error)
//                })
//                guard errorCode == 0 else {
//                    throw RuntimeError("Error in ThresholdKey input_factor_key \(errorCode)")
//                }
//                completion(.success(()))
//            } catch {
//                completion(.failure(error))
//            }
//        }
//    }

    /// Patch and Inserts a `ShareStore` into `ThresholdKey` using `FactorKey`, useful for insertion before reconstruction to ensure the number of shares meet the minimum threshold.
    ///
    /// - Parameters:
    ///   - factorKey  : The `factorKey` to be inserted
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
//    public func patch_input_factor_key(factorKey: String) async throws {
//        return try await withCheckedThrowingContinuation {
//            continuation in
//            self.patch_input_factor_key(factorKey: factorKey) {
//                result in
//                switch result {
//                case let .success(result):
//                    continuation.resume(returning: result)
//                case let .failure(error):
//                    continuation.resume(throwing: error)
//                }
//            }
//        }
//    }
    
    /// Retrieves all share indexes for a `ThresholdKey`.
    ///
    /// - Returns: Array of String
    ///
    /// - Throws: `RuntimeError`, indicates invalid `ThresholdKey`.
    public func get_shares_indexes() throws -> [String] {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_shares_indexes(pointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_share_indexes")
        }

        let string = String(cString: result!)
        let indexes = try! JSONSerialization.jsonObject(with: string.data(using: String.Encoding.utf8)!, options: .allowFragments) as! [String]
        string_free(result)
        return indexes
    }

    /// Encrypts a message.
    ///
    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func encrypt(msg: String) throws -> String {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
        let msgPointer = UnsafeMutablePointer<Int8>(mutating: (msg as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_encrypt(pointer, msgPointer, curvePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey encrypt")
        }
        let string = String(cString: result!)
        string_free(result)
        return string
    }

    /// Decrypts a message.
    ///
    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func decrypt(msg: String) throws -> String {
        var errorCode: Int32 = -1
        let msgPointer = UnsafeMutablePointer<Int8>(mutating: (msg as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_decrypt(pointer, msgPointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey decrypt")
        }
        let string = String(cString: result!)
        string_free(result)
        return string
    }

    /// Returns last metadata fetched from the cloud.
    ///
    /// - Returns: `Metadata`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_last_fetched_cloud_metadata() throws -> Metadata {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_get_last_fetched_cloud_metadata(pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_last_fetched_cloud_metadata")
        }
        return Metadata(pointer: result)
    }

    /// Returns current metadata transitions not yet synchronised.
    ///
    /// - Returns: `LocalMetadataTransitions`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_local_metadata_transitions() throws -> LocalMetadataTransitions {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_get_local_metadata_transitions(pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_local_metadata_transitions")
        }
        return LocalMetadataTransitions(pointer: result!)
    }
    
    /// Returns add metadata transitions , need sync localmetadata transistion to update server data
    ///
    /// - Parameters:
    ///   - input_json: input in json string
    ///   - private_key: private key used to encrypt and store.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
     public func add_local_metadata_transitions( input_json: String, private_key: String ) throws {
         var errorCode: Int32 = -1

         let curve = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
         let input = UnsafeMutablePointer<Int8>(mutating: (input_json as NSString).utf8String)
         let privateKey = UnsafeMutablePointer<Int8>(mutating: (private_key as NSString).utf8String)
         withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_add_local_metadata_transitions(pointer, input, privateKey, curve, error)})
         guard errorCode == 0 else {
             throw RuntimeError("Error in ThresholdKey add_local_metadata_transitions")
         }
     }

    /// Returns the tKey store for a module.
    ///
    /// - Parameters:
    ///   - moduleName: Specific name of the module.
    ///
    /// - Returns: Array of objects.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_tkey_store(moduleName: String) throws -> [[String: Any]] {
        var errorCode: Int32 = -1

        let modulePointer = UnsafeMutablePointer<Int8>(mutating: (moduleName as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tkey_store(pointer, modulePointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_tkey_store")
        }

        let string = String(cString: result!)
        string_free(result)

        let jsonArray = try! JSONSerialization.jsonObject(with: string.data(using: .utf8)!, options: .allowFragments) as! [[String: Any]]
        return jsonArray
    }

    /// Returns the specific tKey store item json for a module.
    ///
    /// - Parameters:
    ///   - moduleName: Specific name of the module.
    ///   - id: Identifier of the item.
    ///
    /// - Returns: `String`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_tkey_store_item(moduleName: String, id: String) throws -> [String: Any] {
        var errorCode: Int32 = -1
        let modulePointer = UnsafeMutablePointer<Int8>(mutating: (moduleName as NSString).utf8String)

        let idPointer = UnsafeMutablePointer<Int8>(mutating: (id as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_tkey_store_item(pointer, modulePointer, idPointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_tkey_store_item")
        }
        let string = String(cString: result!)
        string_free(result)

        let json = try! JSONSerialization.jsonObject(with: string.data(using: .utf8)!, options: .allowFragments) as! [String: Any]
        return json
    }
    
    
    /// set the general store domain.
    ///
    /// - Parameters:
    ///   - key: key domain to be stored
    ///   - data: json string data t be stored
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func set_general_store_domain( key: String, data: String) throws {
        var errorCode: Int32 = -1
        let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)

        let dataPointer = UnsafeMutablePointer<Int8>(mutating: (data as NSString).utf8String)

        withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_set_general_store_domain(pointer, keyPointer, dataPointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey set_domain_store_item : error Code : \(errorCode)")
        }
    }
    
    
    
    /// Returns the general store domain.
    ///
    /// - Parameters:
    ///   - key: key domain stored
    ///
    /// - Returns: `String` json_string
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_general_store_domain(key: String) throws -> String {
        var errorCode: Int32 = -1
        let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_general_store_domain(pointer, keyPointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_domain_store_item \(errorCode)")
        }
        let string = String(cString: result!)
        string_free(result)

        return string
    }
    
    
    /// delete the general store domain.
    ///
    /// - Parameters:
    ///   - key: key domain to be deleted
    ///
    /// - Returns: `String` json_string
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func delete_general_store_domain(key: String) throws {
        var errorCode: Int32 = -1
        let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_general_store_domain(pointer, keyPointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_domain_store_item")
        }
        let string = String(cString: result!)
        string_free(result)
    }


    /// Returns all shares according to their mapping.
    ///
    /// - Returns: `ShareStorePolyIdIndexMap`
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_shares() throws -> ShareStorePolyIdIndexMap {
        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_shares(pointer, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_shares")
        }
        return try ShareStorePolyIdIndexMap(pointer: result!)
    }

    private func sync_local_metadata_transistions(completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1

                let curvePointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: self.curveN).utf8String)

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_sync_local_metadata_transitions(self.pointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey sync_local_metadata_transistions")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    private func sync_metadata(completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1

                let curvePointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: self.curveN).utf8String)

                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_sync_metadata(self.pointer, curvePointer, error)
                })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey sync_local_metadata_transistions")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Syncronises metadata transitions, only used if manual sync is enabled.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func sync_local_metadata_transistions() async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.sync_local_metadata_transistions {
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
    
    /// create metadata transitions (to all shares), sync to server if manual sync is false.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func sync_metadata() async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.sync_metadata {
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

    /// Returns all shares descriptions.
    ///
    /// - Returns: Array of objects.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_share_descriptions() throws -> [String: [String]] {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_share_descriptions(pointer, error)
        })

        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey get_share_descriptions")
        }

        let string = String(cString: result!)
        string_free(result)

        let json = try! JSONSerialization.jsonObject(with: string.data(using: .utf8)!, options: .allowFragments) as! [String: [String]]
        return json
    }

    private func add_share_description(key: String, description: String, update_metadata: Bool, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)
                let descriptionPointer = UnsafeMutablePointer<Int8>(mutating: (description as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_add_share_description(self.pointer, keyPointer, descriptionPointer, update_metadata, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey add_share_description")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Adds a share description.
    ///
    /// - Parameters:
    ///   - key: The key, usually the share index.
    ///   - description: Description for the key.
    ///   - update_metadata: Whether the metadata is synced immediately or not.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func add_share_description(key: String, description: String, update_metadata: Bool = true) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.add_share_description(key: key, description: description, update_metadata: update_metadata) {
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

    private func update_share_description(key: String, oldDescription: String, newDescription: String, update_metadata: Bool, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)
                let oldDescriptionPointer = UnsafeMutablePointer<Int8>(mutating: (oldDescription as NSString).utf8String)
                let newDescriptionPointer = UnsafeMutablePointer<Int8>(mutating: (newDescription as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_update_share_description(self.pointer, keyPointer, oldDescriptionPointer, newDescriptionPointer, update_metadata, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey update_share_description")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Updates a share description.
    ///
    /// - Parameters:
    ///   - key: The relevant key.
    ///   - oldDescription: Old description used for the key
    ///   - newDescription: New description for the key.
    ///   - update_metadata: Whether the metadata is synced immediately or not.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func update_share_description(key: String, oldDescription: String, newDescription: String, update_metadata: Bool = true) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.update_share_description(key: key, oldDescription: oldDescription, newDescription: newDescription, update_metadata: update_metadata) {
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

    private func delete_share_description(key: String, description: String, update_metadata: Bool, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)
                let descriptionPointer = UnsafeMutablePointer<Int8>(mutating: (description as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in
                    threshold_key_delete_share_description(self.pointer, keyPointer, descriptionPointer, update_metadata, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey delete_share_description")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Deletes a share description.
    ///
    /// - Parameters:
    ///   - key: The relevant key.
    ///   - description: Current description for the key.
    ///   - update_metadata: Whether the metadata is synced immediately or not.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func delete_share_description(key: String, description: String, update_metadata: Bool = true) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.delete_share_description(key: key, description: description, update_metadata: update_metadata) {
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

    private func storage_layer_get_metadata(private_key: String?, completion: @escaping (Result<String, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                var privateKeyPointer: UnsafeMutablePointer<Int8>?
                if private_key != nil {
                    privateKeyPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: private_key!).utf8String)
                }
                let ptr = withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_get_metadata(self.pointer, privateKeyPointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey get_metadata")
                }
                let string = String(cString: ptr!)
                string_free(ptr)
                completion(.success(string))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Function to retrieve the metadata directly from the network, only used in very specific instances.
    ///
    /// - Parameters:
    ///   - private_key: The reconstructed key, optional.
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func storage_layer_get_metadata(private_key: String?) async throws -> String {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.storage_layer_get_metadata(private_key: private_key) {
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

    private func storage_layer_set_metadata(private_key: String?, json: String, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                var privateKeyPointer: UnsafeMutablePointer<Int8>?
                if private_key != nil {
                    privateKeyPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: private_key!).utf8String)
                }
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let valuePointer = UnsafeMutablePointer<Int8>(mutating: (json as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_set_metadata(self.pointer, privateKeyPointer, valuePointer, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey set_metadata")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Function to set the metadata directly to the network, only used for specific instances.
    ///
    /// - Parameters:
    ///   - private_key: The reconstructed key.
    ///   - json: Relevant json to be set
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func storage_layer_set_metadata(private_key: String?, json: String) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.storage_layer_set_metadata(private_key: private_key, json: json) {
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

    private func storage_layer_set_metadata_stream(private_keys: String, json: String, completion: @escaping (Result<Void, Error>) -> Void) {
        tkeyQueue.async {
            do {
                var errorCode: Int32 = -1
                let privateKeysPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: private_keys).utf8String)
                let curvePointer = UnsafeMutablePointer<Int8>(mutating: (self.curveN as NSString).utf8String)
                let valuesPointer = UnsafeMutablePointer<Int8>(mutating: (json as NSString).utf8String)
                withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_set_metadata_stream(self.pointer, privateKeysPointer, valuesPointer, curvePointer, error) })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in ThresholdKey set_metadata_stream")
                }
                completion(.success(()))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Function to set the metadata directly to the network, only used for specific instances.
    ///
    /// - Parameters:
    ///   - private_keys: The relevant private keys.
    ///   - json: Relevant json to be set
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func storage_layer_set_metadata_stream(private_keys: String, json: String) async throws {
        return try await withCheckedThrowingContinuation {
            continuation in
            self.storage_layer_set_metadata_stream(private_keys: private_keys, json: json) {
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

    /// Function to assign a public key to the service provider, used only for TSS
    ///
    /// - Parameters:
    ///   - tag: The tss tag
    ///   - nonce: The tss nonce
    ///   - public_key: The pulic key to be assigned
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func service_provider_assign_public_key(tag: String, nonce: String, public_key: String) throws {
        var errorCode: Int32 = -1
        let tagPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: tag).utf8String)
        let noncePointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: nonce).utf8String)
        let publicPointer = UnsafeMutablePointer<Int8>(mutating: NSString(string: public_key).utf8String)
        withUnsafeMutablePointer(to: &errorCode, { error in threshold_key_service_provider_assign_tss_public_key(self.pointer, tagPointer, noncePointer, publicPointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ThresholdKey, service_provider_assign_public_key")
        }
    }

    
    /// Function to get all tss tags
    ///
    /// - Returns: Array of String
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_all_tss_tags() throws -> [String] {
        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_all_tss_tags(self.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_all_tss_tags")
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
    
    /// Function to get extended verifier id
    ///
    /// - Returns: String
    ///
    /// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
    public func get_extended_verifier_id() throws -> String {
        var errorCode: Int32 = -1

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            threshold_key_get_extended_verifier_id(self.pointer, error) })
        guard errorCode == 0 else {
            throw RuntimeError("Error in get_extended_verifier_id")
        }
        let string = String(cString: result!)
        string_free(result)
        return string
    }

    deinit {
        threshold_key_free(pointer)
    }
}
