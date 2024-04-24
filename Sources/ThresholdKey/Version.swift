import Foundation
#if canImport(lib)
    import lib
#endif

/// Returns the library version.
///
/// - Returns: `String`.
///
/// - Throws: `RuntimeError`, underlying library problem.
public func library_version() throws -> String {
    var errorCode: Int32 = -1
    let result = withUnsafeMutablePointer(to: &errorCode, { error in
        get_version(error)
    })

    guard errorCode == 0 else {
        throw RuntimeError("Error in retrieving library version")
    }

    let version = String.init(cString: result!)
    string_free(result)
    return version
}
