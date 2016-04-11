//
//  extensions.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/13/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

extension String {
  var bytes: [UInt8] {
    return [UInt8](self.utf8)
  }
  
  var bytesFromHex: [UInt8]? {
    var result = [UInt8]()
    var i = self.characters.startIndex
    while i != self.characters.endIndex {
      if let character = UInt8(substringWithRange(i ..< i.advancedBy(2)), radix: 16) {
        result.append(character);
      } else {
        return nil
      }
      i = i.advancedBy(2)
    }
    
    return result
  }
  
  var bytesFromBase64: [UInt8]? {
    let bytes = self.bytes
    guard bytes.count % 4 == 0 && bytes.count > 0 else {return nil}
    
    var result: [UInt8] = [UInt8]()
    for i in 0.stride(to: bytes.count, by: 4) {
      let chars: [UInt8] = bytes[i ... i + 3].map({ (byte) -> UInt8 in
        // TODO: replace with switch
        if byte >= "A".utf8.first! && byte <= "Z".utf8.first! {
          return byte - "A".utf8.first!
        }
        if byte >= "a".utf8.first! && byte <= "z".utf8.first! {
          return byte - "a".utf8.first! + 26
        }
        if byte >= "0".utf8.first! && byte <= "9".utf8.first! {
          return byte - "0".utf8.first! + 26 * 2
        }
        if (byte == "=".utf8.first!) {
          return 0
        }
        return byte == "+".utf8.first! ? 62 : 63
      })
      let out1 = chars[0] << 2 | chars[1] >> 4
      let out2 = chars[1] << 4 | chars[2] >> 2
      let out3 = chars[2] << 6 | chars[3] >> 0
      result.appendContentsOf([out1, out2, out3])
    }
    if bytes.last! == "=".utf8.first! {
      result.removeLast()
    }
    if bytes[bytes.count - 2] == "=".utf8.first! {
      result.removeLast()
    }
    return result
  }
}

extension CollectionType where Generator.Element == UInt8, Index == Int {
  var stringRepresentation: String {
    guard let result = String(bytes: self, encoding: NSUTF8StringEncoding) else { fatalError() }
    return result
  }
  
  var hexRepresentation: [UInt8] {
    var result = [UInt8]()
    let values: [UInt8] = "0123456789abcdef".bytes
    for char in self {
      result.append(values[Int(char / 16)])
      result.append(values[Int(char % 16)])
    }
    return result
  }
  
  var hexStringRepresentation: String {
    return self.hexRepresentation.stringRepresentation
  }
  
  var base64Representation: String {
    let values = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".bytes
    var result = [UInt8]()
    for i in self.startIndex.stride(to: self.count, by: 3) {
      let in1 = self[i + 0]
      let in2 = i + 1 < self.count ? self[i + 1] : 0
      let in3 = i + 2 < self.count ? self[i + 2] : 0
      
      let out1 =   in1 >> 2
      let out2 = ((in1 << 6) >> 2) | in2 >> 4
      let out3 = ((in2 << 4) >> 2) | in3 >> 6
      let out4 =   in3 & (~0 >> 2)
      result.appendContentsOf([out1, out2, out3, out4].map{ values[Int($0)] })
    }
    
    let padding = (3 - (self.count % 3)) % 3 // 🙃💩😞
    result[result.count - padding ..< result.count] = "==".bytes[0 ..< padding]
    
    return result.stringRepresentation
  }
}