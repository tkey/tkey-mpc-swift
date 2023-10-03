//
//  File.swift
//  
//
//  Created by CW Lee on 26/09/2023.
//

import Foundation


func selectedServerToPointer (selectedServers: [UInt32]?) throws -> UnsafeMutablePointer<Int8>? {
    guard let selectedServers = selectedServers else {
        return nil
    }
    var serversPointer: UnsafeMutablePointer<Int8>?
    
    let selected_servers_json = try JSONSerialization.data(withJSONObject: selectedServers as Any)
    let selected_servers_str = String(data: selected_servers_json, encoding: .utf8)!
    print(selected_servers_str)
    serversPointer = UnsafeMutablePointer<Int8>(mutating: (selected_servers_str as NSString).utf8String)

    guard let serversPointer = serversPointer else {
        throw RuntimeError("convert error")
    }
    return serversPointer
}

func authSignaturesToPointer ( authSignatures : [String]?) throws -> UnsafeMutablePointer<Int8>? {
    guard let authSignatures = authSignatures else {
        return nil
    }
    let auth_signatures_json = try JSONSerialization.data(withJSONObject: authSignatures)
    guard let auth_signatures_str = String(data: auth_signatures_json, encoding: .utf8) else {
        throw RuntimeError("auth signatures error")
    }
    print(authSignatures)
    print(auth_signatures_str.count)

    let authSignaturesPointer = UnsafeMutablePointer<Int8>(mutating: (auth_signatures_str as NSString).utf8String)
    
    
    return authSignaturesPointer
}

