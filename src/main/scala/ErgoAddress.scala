package org.ergoplatform.simpleaddresses

import java.util

import scorex.util.encode.Base58

import scala.util.{Failure, Success, Try}
import ErgoAddressEncoder._
import org.ergoplatform.Blake2b256Wrapper

/**
  * An address is a short string corresponding to some script used to protect a box. Unlike (string-encoded) binary
  * representation of a script, an address has some useful characteristics:
  *
  * - Integrity of an address could be checked., as it is incorporating a checksum.
  * - A prefix of address is showing network and an address type.
  * - An address is using an encoding (namely, Base58) which is avoiding similarly l0Oking characters, friendly to
  * double-clicking and line-breaking in emails.
  *
  *
  *
  * An address is encoding network type, address type, checksum, and enough information to watch for a particular scripts.
  *
  * Possible network types are:
  * Mainnet - 0x00
  * Testnet - 0x10
  *
  * Address types are, semantics is described below:
  * 0x01 - Pay-to-PublicKey(P2PK) address
  * 0x02 - Pay-to-Script-Hash(P2SH)
  * 0x03 - Pay-to-Script(P2S)
  *
  * For an address type, we form content bytes as follows:
  *
  * P2PK - serialized (compressed) public key
  * P2SH - first 192 bits of the Blake2b256 hash of serialized script bytes
  * P2S  - serialized script
  *
  * Address examples for testnet:
  *
  * 3   - P2PK (3WvsT2Gm4EpsM9Pg18PdY6XyhNNMqXDsvJTbbf6ihLvAmSb7u5RN)
  * ?   - P2SH (rbcrmKEYduUvADj9Ts3dSVSG27h54pgrq5fPuwB)
  * ?   - P2S (Ms7smJwLGbUAjuWQ)
  *
  * for mainnet:
  *
  * 9  - P2PK (9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA)
  * ?  - P2SH (8UApt8czfFVuTgQmMwtsRBZ4nfWquNiSwCWUjMg)
  * ?  - P2S (4MQyML64GnzMxZgm, BxKBaHkvrTvLZrDcZjcsxsF7aSsrN73ijeFZXtbj4CXZHHcvBtqSxQ)
  *
  *
  * Prefix byte = network type + address type
  *
  * checksum = blake2b256(prefix byte ++ content bytes)
  *
  * address = prefix byte ++ content bytes ++ checksum
  *
  */
sealed trait ErgoAddress {
  /** Address type code used to differentiate between pay-to-public-key, pay-to-script,
    * pay-to-script-hash addresses.
    *
    * NOTE: Network type code is defined by [[ErgoAddressEncoder]] attached to each ErgoAddress
    * instance and it is not included in this value.
    *
    * @see [[P2PKAddress]], [[Pay2SAddress]], [[Pay2SHAddress]]
    */
  val addressTypePrefix: Byte

  /** Serialized bytes of the address content (depending on the address type).
    * Doesn't include network type and address type prefix byte.
    * @see [[P2PKAddress]], [[Pay2SAddress]], [[Pay2SHAddress]]
    */
  val contentBytes: Array[Byte]


  /** Network type code to be used in address encoding. */
  def networkPrefix: NetworkPrefix
}

/** Implementation of pay-to-public-key [[ErgoAddress]]. */
case class P2PKAddress(pubkeyBytes: Array[Byte])(implicit val encoder: ErgoAddressEncoder) extends ErgoAddress {

  override val addressTypePrefix: Byte = P2PKAddress.addressTypePrefix

  override val contentBytes: Array[Byte] = pubkeyBytes

  override def networkPrefix: NetworkPrefix = encoder.networkPrefix

  override def equals(obj: Any): Boolean = obj match {
    case p2pk: P2PKAddress => util.Arrays.equals(pubkeyBytes, p2pk.pubkeyBytes)
    case _ => false
  }

  override def toString: String = encoder.toString(this)
}

object P2PKAddress {
  /** Value added to the prefix byte in the serialized bytes of an encoded P2PK address.
    * @see [[ErgoAddressEncoder.toString]]
    */
  val addressTypePrefix: Byte = 1: Byte


}

/** Implementation of pay-to-script-hash [[ErgoAddress]]. */
class Pay2SHAddress(val scriptHash: Array[Byte])(implicit val encoder: ErgoAddressEncoder) extends ErgoAddress {
  override val addressTypePrefix: Byte = Pay2SHAddress.addressTypePrefix

  override val contentBytes: Array[Byte] = scriptHash

  override def networkPrefix: NetworkPrefix = encoder.networkPrefix

  override def equals(obj: Any): Boolean = obj match {
    case p2sh: Pay2SHAddress => util.Arrays.equals(scriptHash, p2sh.scriptHash)
    case _ => false
  }

  override def toString: String = encoder.toString(this)
}

object Pay2SHAddress {
  /** Value added to the prefix byte in the serialized bytes of an encoded P2SH address.
    * @see [[ErgoAddressEncoder.toString]]
    */
  val addressTypePrefix: Byte = 2: Byte

}

/** Implementation of pay-to-script [[ErgoAddress]]. */
class Pay2SAddress(val scriptBytes: Array[Byte])
                  (implicit val encoder: ErgoAddressEncoder) extends ErgoAddress {
  override val addressTypePrefix: Byte = Pay2SAddress.addressTypePrefix

  override val contentBytes: Array[Byte] = scriptBytes

  override def networkPrefix: NetworkPrefix = encoder.networkPrefix

  override def equals(obj: Any): Boolean = obj match {
    case p2s: Pay2SAddress => util.Arrays.equals(scriptBytes, p2s.scriptBytes)
    case _ => false
  }

  override def toString: String = encoder.toString(this)
}

object Pay2SAddress {
  /** Value added to the prefix byte in the serialized bytes of an encoded P2S address.
    * @see [[ErgoAddressEncoder.toString()]]
    */
  val addressTypePrefix: Byte = 3: Byte

}

/** Network-aware encoder for ErgoAddress <-> Base58String conversions.
  * @param networkPrefix network prefix value to be used in address encoding.
  */
class ErgoAddressEncoder(val networkPrefix: NetworkPrefix) {

  import ErgoAddressEncoder._

  /** This value is be used implicitly in the methods below. */
  implicit private def ergoAddressEncoder: ErgoAddressEncoder = this

  /** Converts the given [[ErgoAddress]] to Base58 string. */
  def toString(address: ErgoAddress): String = {
    val withNetworkByte = (networkPrefix + address.addressTypePrefix).toByte +: address.contentBytes

    val checksum = hash256(withNetworkByte).take(ChecksumLength)
    Base58.encode(withNetworkByte ++ checksum)
  }

  /** Returns true if the given `addrHeadByte` is a header byte of a testnet address, false otherwise. */
  def isTestnetAddress(addrHeadByte: Byte): Boolean = addrHeadByte > TestnetNetworkPrefix

  /** Returns true if the given `addrHeadByte` is a header byte of a mainnet address, false otherwise. */
  def isMainnetAddress(addrHeadByte: Byte): Boolean = addrHeadByte < TestnetNetworkPrefix

  /** Converts the given Base58 string to [[ErgoAddress]] or an error packed in Try. */
  def fromString(addrBase58Str: String): ErgoAddress = {
    val resTry = Base58.decode(addrBase58Str).flatMap { bytes =>
      Try {
        val headByte = bytes.head
        networkPrefix match {
          case TestnetNetworkPrefix => require(isTestnetAddress(headByte), "Trying to decode mainnet address in testnet")
          case MainnetNetworkPrefix => require(isMainnetAddress(headByte), "Trying to decode testnet address in mainnet")
        }
        val addressType = (headByte - networkPrefix).toByte
        val (withoutChecksum, checksum) = bytes.splitAt(bytes.length - ChecksumLength)

        if (!util.Arrays.equals(hash256(withoutChecksum).take(ChecksumLength), checksum)) {
          throw new Exception(s"Checksum check fails for $addrBase58Str")
        }

        val contentBytes = withoutChecksum.tail

        addressType match {
          case P2PKAddress.addressTypePrefix =>
            new P2PKAddress(contentBytes)
          case Pay2SHAddress.addressTypePrefix =>
            if (contentBytes.length != 24) { //192-bits hash used
              throw new Exception(s"Improper content in P2SH script: $addrBase58Str")
            }
            new Pay2SHAddress(contentBytes)
          case Pay2SAddress.addressTypePrefix =>
            new Pay2SAddress(contentBytes)
          case _ =>
            throw new Exception(s"Unsupported address type: $addressType")
        }
      }
    }

    resTry match {
      case Success(address) => address
      case Failure(exception) => throw exception
    }
  }
}

object ErgoAddressEncoder {
  /** Type of the network prefix value. */
  type NetworkPrefix = Byte

  /** Value of the prefix byte used to encode Mainnet ErgoAddress. */
  val MainnetNetworkPrefix: NetworkPrefix = 0.toByte

  /** Value of the prefix byte used to encode Testnet ErgoAddress. */
  val TestnetNetworkPrefix: NetworkPrefix = 16.toByte

  /** Length of the checksum section of encoded ergo address bytes. */
  val ChecksumLength = 4

  /** Helper method to hash the given array using Blake2b256. */
  def hash256(input: Array[Byte]) = Blake2b256Wrapper.hash(input)

  /** Helper method to hash the given array using Blake2b256 and take first 192 bit (24 bytes). */
  def hash192(input: Array[Byte]): Array[Byte] = hash256(input).take(24)
}

class MainnetAddressEncoder() extends ErgoAddressEncoder(ErgoAddressEncoder.MainnetNetworkPrefix)
class TestnetAddressEncoder() extends ErgoAddressEncoder(ErgoAddressEncoder.TestnetNetworkPrefix)