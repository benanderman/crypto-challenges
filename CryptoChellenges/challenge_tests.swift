//
//  challenge_tests.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/16/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

func testChallenges() {
  
  let crypto = Crypto()
  
  func testAllChallenges() {
    testBase64()
    testHammingDistance()
    testChallenge1()
    testChallenge2()
    testChallenge3()
    testChallenge4()
    testChallenge5()
    testChallenge6()
  }
  
  testAllChallenges()
  
  func testChallenge1() {
    let base64TestInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    if let result = crypto.hexToBase64(base64TestInput) {
      print("\(base64TestInput)\nhexToBase64:\n\(result)\n")
    } else {
      print("Failed to convert\n")
    }
  }
  
  func testChallenge2() {
    let xorTestInput1 = "1c0111001f010100061a024b53535009181c"
    let xorTestInput2 = "686974207468652062756c6c277320657965"
    if let output = crypto.xorHexStrings(xorTestInput1, hex2: xorTestInput2) {
      print("\(xorTestInput1), \(xorTestInput2)\nxorHexStrings:\n\(output)\n")
    } else {
      print("Failed to xor\n")
    }
  }
  
  func testChallenge3() {
    let singleByteXorInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    if let output3 = crypto.decipherSingleByteXorHex([singleByteXorInput]) {
      print(singleByteXorInput + "\ndecipherSingleByteXorHex:\n" + output3 + "\n")
    } else {
      print("Failed to decipher\n")
    }
  }
  
  func testChallenge4() {
    do {
      let singleByteXor2Input = try NSString(contentsOfFile: "4.txt", encoding: NSUTF8StringEncoding)
      let lines = singleByteXor2Input.componentsSeparatedByString("\r\n")
      if let result = crypto.decipherSingleByteXorHex(lines) {
        print("decipherSingleByteXorHex (with 4.txt):\n\(result)\n")
      } else {
        print("Failed to decipher\n")
      }
    } catch {
      print("Failed to read input file\n")
    }
  }
  
  func testChallenge5() {
    let repeatingByteCipherInput = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    let result = crypto.cipherStringWithKey(repeatingByteCipherInput, key: "ICE".bytes)
    print("\(repeatingByteCipherInput)\ncipherStringWithKey('ICE'):\n\(result)\n")
  }
  
  func testChallenge6() {
    do {
      var repeatingByteDecipherInput = try NSString(contentsOfFile: "6.txt", encoding: NSUTF8StringEncoding)
      repeatingByteDecipherInput = repeatingByteDecipherInput.stringByReplacingOccurrencesOfString("\r\n", withString: "")
      if let result = crypto.decipherRepeatingKeyXorBase64(String(repeatingByteDecipherInput)) {
        print("decipherRepeatingKeyXorBase64 (with 6.txt):\nKey: \(result.key.stringRepresentation)\n\(result.result)\n")
      } else {
        print("Failed to decipher")
      }
    } catch {
      print("Failed to read input file\n")
    }
  }
  
  func testHammingDistance() {
    let hammingInput1 = "this is a test"
    let hammingInput2 = "wokka wokka!!!"
    let resultInt = crypto.editDistance(hammingInput1.bytes, data2: hammingInput2.bytes)
    // Should be 37
    print("editDistance('\(hammingInput1)', '\(hammingInput2)') = \(resultInt)\n")
  }
  
  func testBase64() {
    let inputs = ["1234", "12345", "123456"]
    for input in inputs {
      if let result = input.bytes.base64Representation.bytesFromBase64?.stringRepresentation {
        print("\(input) round trip base64 = \(result)\n")
      } else {
        print("Failed to convert \(input) to base64 and back\n")
      }
    }
  }
}