//
//  main.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/10/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

let crypto: Crypto = Crypto()

let base64TestInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
var result = String(bytes: crypto.hexToBase64([UInt8](base64TestInput.utf8))!, encoding: NSUTF8StringEncoding)
if let output = result {
  print(base64TestInput + "\nhexToBase64:\n" + output + "\n")
} else {
  print("Failed to convert")
}

let xorTestInput1 = "1c0111001f010100061a024b53535009181c"
let xorTestInput2 = "686974207468652062756c6c277320657965"
result = String(bytes: crypto.xorHexStrings([UInt8](xorTestInput1.utf8), hex2: [UInt8](xorTestInput2.utf8))!, encoding: NSUTF8StringEncoding)
if let output2 = result {
  print(xorTestInput1 + ", " + xorTestInput2 + "\nxorHexStrings:\n" + output2 + "\n")
} else {
  print("Failed to xor")
}

let singleByteXorInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
result = String(bytes: crypto.decipherSingleByteXorHex([[UInt8]](arrayLiteral: [UInt8](singleByteXorInput.utf8)))!, encoding: NSUTF8StringEncoding)
if let output3 = result {
  print(singleByteXorInput + "\ndecipherSingleByteXorHex:\n" + output3 + "\n")
} else {
  print("Failed to decipher")
}

do {
  let singleByteXor2Input = try NSString(contentsOfFile: "/Volumes/HD/programming_stuff/exercises/crypto/4.txt", encoding: NSUTF8StringEncoding)
  let lines = singleByteXor2Input.componentsSeparatedByString("\r\n")
  result = String(bytes: crypto.decipherSingleByteXorHex(lines.map { [UInt8]($0.utf8) })!, encoding: NSUTF8StringEncoding)
  if let output4 = result {
    print("decipherSingleByteXorHex (with 4.txt):\n" + output4 + "\n")
  } else {
    print("Failed to decipher")
  }
} catch {
  print("Failed to read input file")
}

let repeatingByteCipherInput = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
result = String(bytes: crypto.cipherStringWithKey([UInt8](repeatingByteCipherInput.utf8), key: [UInt8]("ICE".utf8)), encoding: NSUTF8StringEncoding)
if let output5 = result {
  print(repeatingByteCipherInput + "\ncipherStringWithKey('ICE'):\n" + output5 + "\n")
} else {
  print("Failed to decipher")
}

