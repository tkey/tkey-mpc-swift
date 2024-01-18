import Foundation
#if canImport(tkey)
    import tkey
#endif

public final class KeyDetails {
    public let pub_key: KeyPoint
    public let required_shares: Int32
    public let threshold: UInt32
    public let total_shares: UInt32
    public let share_descriptions: String

    /// Instantiate a `KeyDetails` object using the underlying pointer.
    ///
    /// - Parameters:
    ///   - pointer: The pointer to the underlying foreign function interface object.
    ///
    /// - Returns: `KeyDetails`
    ///
    /// - Throws: `RuntimeError`, indicates underlying pointer is invalid.
    public init(pointer: OpaquePointer) throws {
        var errorCode: Int32 = -1
        let point = withUnsafeMutablePointer(to: &errorCode, { error in
           key_details_get_pub_key_point(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Point")
            }
        pub_key = KeyPoint.init(pointer: point!)

        let theshold = withUnsafeMutablePointer(to: &errorCode, { error in
           key_details_get_threshold(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Threshold")
            }
        self.threshold = theshold

        let required_shares = withUnsafeMutablePointer(to: &errorCode, { error in
           key_details_get_required_shares(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Required Shares")
            }
        self.required_shares = required_shares

        let total_shares = withUnsafeMutablePointer(to: &errorCode, { error in
           key_details_get_total_shares(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Total Shares")
            }
        self.total_shares = total_shares

        let share_descriptions = withUnsafeMutablePointer(to: &errorCode, { error in
           key_details_get_share_descriptions(pointer, error)
               })
        guard errorCode == 0 else {
            throw RuntimeError("Error in KeyDetails, field Share Descriptions")
            }
        self.share_descriptions = String.init(cString: share_descriptions!)
        string_free(share_descriptions)
        key_details_free(pointer)
    }
}
