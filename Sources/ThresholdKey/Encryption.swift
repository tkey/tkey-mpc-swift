//
//  File.swift
//  
//
//  Created by CW Lee on 12/09/2023.
//

import Foundation
#if canImport(lib)
    import lib
#endif

// secp256k1 curve
public let secpN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"


/// Encrypts a message.
///
/// - Returns: `String`
///
/// - Throws: `RuntimeError`, indicates invalid parameters or invalid `ThresholdKey`.
public func encrypt(key: String, msg: String, curveN: String = secpN ) throws -> String {
    var errorCode: Int32 = -1
    let curvePointer = UnsafeMutablePointer<Int8>(mutating: (curveN as NSString).utf8String)
    let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)
    let msgPointer = UnsafeMutablePointer<Int8>(mutating: (msg as NSString).utf8String)

    let result = withUnsafeMutablePointer(to: &errorCode, { error in
        tkey_encrypt(keyPointer, msgPointer, curvePointer, error)
    })
    guard errorCode == 0 else {
        throw RuntimeError("Error in encrypt \(errorCode)")
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
public func decrypt(key: String, msg: String) throws -> String {
    var errorCode: Int32 = -1
    let keyPointer = UnsafeMutablePointer<Int8>(mutating: (key as NSString).utf8String)
    let msgPointer = UnsafeMutablePointer<Int8>(mutating: (msg as NSString).utf8String)

    let result = withUnsafeMutablePointer(to: &errorCode, { error in
        tkey_decrypt(keyPointer, msgPointer, error)
    })
    guard errorCode == 0 else {
        throw RuntimeError("Error in decrypt \(errorCode)")
    }
    let string = String(cString: result!)
    string_free(result)
    return string
}
