import Foundation
#if canImport(tkey)
    import tkey
#endif

public final class KeyReconstructionDetails: Codable {
    public var key: String
    public var seed_phrase: [String]
    public var all_keys: [String]

    /// Instantiate a `KeyReconstructionDetails` object using the underlying pointer.
    ///
    /// - Parameters:
    ///   - pointer: The pointer to the underlying foreign function interface object.
    ///
    /// - Returns: `KeyReconstructionDetails`
    ///
    /// - Throws: `RuntimeError`, indicates underlying pointer is invalid.
    public init(pointer: OpaquePointer) throws {
        var errorCode: Int32 = -1
        let key = withUnsafeMutablePointer(to: &errorCode, { error in
           key_reconstruction_get_private_key(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Private Key")
            }
        self.key = String.init(cString: key!)
        string_free(key)

        self.seed_phrase = []
        let seed_len = withUnsafeMutablePointer(to: &errorCode, { error in
           key_reconstruction_get_seed_phrase_len(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Seed Phrase")
            }
        if seed_len > 0 {
            for index in 0...seed_len-1 {
                let seed_item = withUnsafeMutablePointer(to: &errorCode, { error in
                   key_reconstruction_get_seed_phrase_at(pointer, index, error)
                       })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in KeyDetails, field Seed Phrase, index " + String(index))
                    }
                self.seed_phrase.append(String.init(cString: seed_item!))
                string_free(seed_item)
            }
        }

        self.all_keys = []
        let keys_len = withUnsafeMutablePointer(to: &errorCode, { error in
           key_reconstruction_get_all_keys_len(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Seed Phrase")
            }
        if keys_len > 0 {
            for index in 0...keys_len-1 {
                let seed_item = withUnsafeMutablePointer(to: &errorCode, { error in
                   key_reconstruction_get_all_keys_at(pointer, index, error)
                       })
                guard errorCode == 0 else {
                    throw RuntimeError("Error in KeyDetails, field Seed Phrase, index " + String(index))
                    }
                self.all_keys.append(String.init(cString: seed_item!))
                string_free(seed_item)
            }
        }

        key_reconstruction_details_free(pointer)
    }
}
