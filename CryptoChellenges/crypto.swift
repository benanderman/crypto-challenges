//
//  crypto.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/10/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

enum AsciiRange: Int {
  case Lower, Upper, Space, Symbol, Bad, Other
  init(value: UInt8) {
    self = Other
    if value >= "a".utf8.first! && value <= "z".utf8.first! {
      self = Lower
    }
    if value >= "A".utf8.first! && value <= "Z".utf8.first! {
      self = Upper
    }
    if value == " ".utf8.first! {
      self = Space
    }
    if (value > 32 && value < 48) || (value > 57 && value < 65) || (value > 90 && value < 97) || value > 122 {
      self = Symbol
    }
    if (value < 32 && value != 10 && value != 13) || value > 127 {
      self = Bad
    }
  }
}

class Crypto {
  func hexToBase64(hex: [UInt8]) -> [UInt8]? {
    if let rawValues = hexToRaw(hex) {
      var result: [UInt8] = [UInt8]()
      for var i = 0; i < rawValues.count; i += 3 {
        let char1 = rawValues[i + 0] >> 2
        let char2 = ((rawValues[i + 0] << 6) >> 2) | rawValues[i + 1] >> 4
        let char3 = ((rawValues[i + 1] << 4) >> 2) | rawValues[i + 2] >> 6
        let char4 = rawValues[i + 2] & (~0 >> 2)
        result.appendContentsOf([char1, char2, char3, char4].map({ (char) -> UInt8 in
          if char < 26 {
            return "A".utf8.first! + char
          }
          if char < 26 * 2 {
            return "a".utf8.first! + (char - 26)
          }
          if (char < 26 * 2 + 10) {
            return "0".utf8.first! + (char - 26 * 2)
          }
          return char == 62 ? "+".utf8.first! : "/".utf8.first!
        }))
      }
      
      return result
    }
    return nil
  }
  
  func xorHexStrings(hex1: [UInt8], hex2: [UInt8]) -> [UInt8]? {
    if (hex1.count != hex2.count) {
      return nil
    }
    if let raw1 = hexToRaw(hex1), let raw2 = hexToRaw(hex2) {
      var result: [UInt8] = [UInt8]()
      for i in 0 ..< raw1.count {
        result.append(raw1[i] ^ raw2[i])
      }
      return result
    }
    return nil
  }
  
  func decipherRepeatingKeyXorBase64(input: [UInt8]) -> [UInt8]? {
    if let raw = base64ToRaw(input) {
      var keySize = 0
      var bestEditDistance = Double.infinity
      for i in 2 ... 40 {
        var distances:[Double] = [Double]()
        for o in raw.startIndex.stride(to: raw.endIndex - i * 2, by: i) {
          let distance = Double(editDistance([UInt8](raw[o ..< o + i]), data2: [UInt8](raw[o + i ..< o + i * 2]))) / Double(i * 8)
          distances.append(distance)
        }
        let distance = distances.reduce(0) { $0 + $1 } / Double(distances.count)
        if (distance < bestEditDistance) {
          bestEditDistance = distance
          keySize = i
        }
      }
      
      var blocks:[[UInt8]] = [[UInt8]]()
      for i in 0 ..< keySize {
        var block:[UInt8] = [UInt8]()
        for j in i.stride(to: raw.count, by: keySize) {
          block.append(raw[j])
        }
        let decoded = decipherSingleByteXor([[UInt8]](arrayLiteral: block))
        blocks.append(decoded)
      }
      
      if (blocks.count == 0) {
        return nil
      }
      var result:[UInt8] = [UInt8]()
      for i in 0 ..< blocks.first!.count {
        for block in blocks {
          if i < block.count {
            result.append(block[i])
          }
        }
      }
      return result
    }
    return nil
  }
  
  func decipherSingleByteXor(inputs: [[UInt8]]) -> [UInt8] {
    var bestScore = -100
    var bestResult = [UInt8]()
    for raw in inputs {
      for i in 0 ..< 256 {
        let deciphered = decipherSingleByteXor(raw, key: UInt8(i))
        let score = textScoreForString(deciphered)
        if (score > bestScore) {
          bestScore = score
          bestResult = deciphered
        }
      }
    }
    return bestResult
  }
  
  func decipherSingleByteXorHex(inputs: [[UInt8]]) -> [UInt8]? {
    return decipherSingleByteXor(inputs.map({
      return hexToRaw($0)!
    }))
  }
  
  func textScoreForString(text: [UInt8]) -> Int {
    var counts: Dictionary<AsciiRange, Int> = Dictionary<AsciiRange, Int>()
    for char in text {
      let range = AsciiRange(value: char)
      if let count = counts[range] {
        counts[range] = count + 1
      } else {
        counts[range] = 1
      }
    }
    
    var score = 0
    let lowerCount = counts[AsciiRange.Lower] ?? 0
    let upperCount = counts[AsciiRange.Upper] ?? 0
    let spaceCount = counts[AsciiRange.Space] ?? 0
    let symbolCount = counts[AsciiRange.Symbol] ?? 0
    let badCount = counts[AsciiRange.Bad] ?? 0
    
    score += Int((1 - abs(Double(lowerCount) / Double(text.count) - 0.75)) * 300)
    score += Int((1 - abs(Double(upperCount) / Double(text.count) - 0.2)) * 50)
    let spaceRatio = Double(spaceCount) / Double(text.count)
    score += Int((1 - abs(spaceRatio - 0.17)) * 100)
    if spaceRatio > 0 && spaceRatio < 0.8 {
      score += 500
    }
    let symbolRatio = Double(symbolCount) / Double(text.count)
    if symbolRatio > 0.5 {
      score -= Int(symbolRatio * Double(900))
    }
    
    score += Int(Double(badCount) / Double(text.count) * -900)
    
//    if let string = String(bytes: text, encoding: NSUTF8StringEncoding) {
//      print("\(string): \(score)")
//    }
    
    return score
  }
  
  func decipherSingleByteXor(string: [UInt8], key: UInt8) -> [UInt8] {
    return string.map { $0 ^ key }
  }
  
  func cipherStringWithKey(string: [UInt8], key: [UInt8]) -> [UInt8] {
    return rawToHex(string.enumerate().map { (index: Int, byte: UInt8) in
      return byte ^ key[index % key.count]
    })
  }
  
  func editDistance(data1: [UInt8], data2: [UInt8]) -> Int {
    if (data1.count != data2.count) {
      return ~0
    }
    var distance = 0
    for i in 0 ..< data1.count {
      for o in 0 ..< 8 {
        if (data1[i] >> UInt8(o)) & 1 != (data2[i] >> UInt8(o)) & 1 {
          distance++
        }
      }
    }
    return distance
  }
  
  func rawToHex(hex: [UInt8]) -> [UInt8] {
    var result: [UInt8] = [UInt8]()
    let values: [UInt8] = [UInt8]("0123456789abcdef".utf8)
    for char in hex {
      result.append(values[Int(char / 16)])
      result.append(values[Int(char % 16)])
    }
    return result
  }
  
  func hexToRaw(hex: [UInt8]) -> [UInt8]? {
    if (hex.count % 2 != 0) {
      return nil // Not a valid hex string
    }
    var rawValues: [UInt8] = [UInt8]()
    for var i = 0; i < hex.count; i += 2 {
      rawValues.append(self.hexCharToInt(hex[i]) * 16 + self.hexCharToInt(hex[i + 1]))
    }
    return rawValues
  }
  
  func base64ToRaw(base64: [UInt8]) -> [UInt8]? {
    if base64.count % 4 != 0 || base64.count == 0 {
      return nil
    }
    
    var result: [UInt8] = [UInt8]()
    for var i = 0; i < base64.count; i += 4 {
      let chars: [UInt8] = base64[i ... i + 3].map({ (char) -> UInt8 in
        if char >= "A".utf8.first! && char <= "Z".utf8.first! {
          return char - "A".utf8.first!
        }
        if char >= "a".utf8.first! && char <= "z".utf8.first! {
          return char - "a".utf8.first! + 26
        }
        if char >= "0".utf8.first! && char <= "9".utf8.first! {
          return char - "0".utf8.first! + 26 * 2
        }
        if (char == "=".utf8.first!) {
          return 0
        }
        return char == "+".utf8.first! ? 62 : 63
      })
      let out1 = chars[0] << 2 | chars[1] >> 4
      let out2 = chars[1] << 4 | chars[2] >> 2
      let out3 = chars[2] << 6 | chars[3] >> 0
      result.appendContentsOf([out1, out2, out3])
    }
    if base64.last! == "=".utf8.first! {
      result.removeLast()
    }
    if base64[base64.count-2] == "=".utf8.first! {
      result.removeLast()
    }
    return result
  }
  
  func hexCharToInt(char: UInt8) -> UInt8 {
    let zero = "0".utf8.first!
    let nine = "9".utf8.first!
    let a = "a".utf8.first!
    let f = "f".utf8.first!
    
    if (char >= zero && char <= nine) {
      return char - zero
    }
    if (char >= a && char <= f) {
      return char - a + 10
    }
    return 0
  }
}
