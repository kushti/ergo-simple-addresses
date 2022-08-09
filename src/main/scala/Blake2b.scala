package org.ergoplatform

import ove.crypto.digest.Blake2b

object Blake2b256Wrapper {

  def hash(input: Array[Byte]): Array[Byte] = {
    val blake2b = Blake2b.Digest.newInstance(32)
    blake2b.digest(input)
  }

}
