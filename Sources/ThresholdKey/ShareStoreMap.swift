import Foundation
#if canImport(lib)
    import lib
#endif

public final class ShareStoreMap {
    public var share_maps = [String: ShareStore]()

    /// Instantiate a `ShareStoreMap` object using the underlying pointer.
    ///
    /// - Parameters:
    ///   - pointer: The pointer to the underlying foreign function interface object.
    ///
    /// - Returns: `ShareStoreMap`
    ///
    /// - Throws: `RuntimeError`, indicates underlying pointer is invalid.
    public init(pointer: OpaquePointer) throws {
        var errorCode: Int32 = -1
        let keys = withUnsafeMutablePointer(to: &errorCode, { error in
            share_store_map_get_keys(pointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in ShareStoreMap")
            }
        let value = String.init(cString: keys!)
        string_free(keys)
        let data = Data(value.utf8)
        let key_array = try JSONSerialization.jsonObject(with: data) as! [String]
        for item in key_array {
            let keyPointer = UnsafeMutablePointer<Int8>(mutating: (item as NSString).utf8String)
            let value = withUnsafeMutablePointer(to: &errorCode, { error in
                share_store_map_get_value_by_key(pointer, keyPointer, error)
                    })
            guard errorCode == 0 else {
                throw RuntimeError("Error in ShareStoreMap")
                }
            share_maps[item] = ShareStore.init(pointer: value!)
        }

        share_store_map_free(pointer)
    }
}
