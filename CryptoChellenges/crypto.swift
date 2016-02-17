//
//  crypto.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/10/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

class Crypto {
  
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
  
  func hexToBase64(hex: String) -> String? {
    return hex.bytesFromHex?.base64Representation
  }
  
  func xorHexStrings(hex1: String, hex2: String) -> String? {
    if (hex1.utf8.count != hex2.utf8.count) {
      return nil
    }
    if let bytes1 = hex1.bytesFromHex, let bytes2 = hex2.bytesFromHex {
      var result: [UInt8] = [UInt8]()
      for i in 0 ..< bytes1.count {
        result.append(bytes1[i] ^ bytes2[i])
      }
      return result.hexStringRepresentation
    }
    return nil
  }
  
  func decipherRepeatingKeyXorBase64(base64: String) -> (result: String, key: [UInt8])? {
    if let raw = base64.bytesFromBase64 {
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
      
      var blocks = [[UInt8]]()
      var key = [UInt8]()
      for i in 0 ..< keySize {
        var block:[UInt8] = [UInt8]()
        for j in i.stride(to: raw.count, by: keySize) {
          block.append(raw[j])
        }
        let decoded = decipherSingleByteXor(block)
        blocks.append(decoded.result)
        key.append(decoded.key)
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
      return (result.stringRepresentation, key)
    }
    return nil
  }
  
  func decipherSingleByteXor(input: [UInt8]) -> (result: [UInt8], key: UInt8, score: Int) {
    var bestScore = Int.min
    var bestResult = [UInt8]()
    var bestKey = 0 as UInt8
    for i in 0 ..< 256 {
      let deciphered = decipherSingleByteXor(input, key: UInt8(i))
      let score = textScoreForData(deciphered)
      if (score > bestScore) {
        bestScore = score
        bestResult = deciphered
        bestKey = UInt8(i)
      }
    }
    return (bestResult, bestKey, bestScore)
  }
  
  func decipherSingleByteXorHex(inputs: [String]) -> String? {
    var bestScore = Int.min
    var bestResult = [UInt8]()
    for input in inputs {
      if let bytes = input.bytesFromHex {
        let (result, _, score) = decipherSingleByteXor(bytes)
        if (score > bestScore) {
          (bestResult, bestScore) = (result, score)
        }
      }
    }
    return bestResult.stringRepresentation
  }
  
  func textScoreForData(data: [UInt8]) -> Int {
    var counts: Dictionary<AsciiRange, Int> = Dictionary<AsciiRange, Int>()
    for char in data {
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
    
    score += Int((1 - abs(Double(lowerCount) / Double(data.count) - 0.75)) * 300)
    score += Int((1 - abs(Double(upperCount) / Double(data.count) - 0.2)) * 50)
    let spaceRatio = Double(spaceCount) / Double(data.count)
    score += Int((1 - abs(spaceRatio - 0.17)) * 100)
    if spaceRatio > 0 && spaceRatio < 0.8 {
      score += 500
    }
    let symbolRatio = Double(symbolCount) / Double(data.count)
    if symbolRatio > 0.5 {
      score -= Int(symbolRatio * Double(900))
    }
    
    score += Int(Double(badCount) / Double(data.count) * -900)
    
    return score
  }
  
  func decipherSingleByteXor(string: [UInt8], key: UInt8) -> [UInt8] {
    return string.map { $0 ^ key }
  }
  
  func cipherStringWithKey(string: String, key: [UInt8]) -> String {
    return string.bytes.enumerate().map({ (index: Int, byte: UInt8) in
      return byte ^ key[index % key.count]
    }).hexStringRepresentation
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
}
