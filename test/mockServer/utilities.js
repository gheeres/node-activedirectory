/**
 * Generate a semi-random Sid/GUID i.e. for an objectSid
 * Mimicks the Sids returned by AD in terms of datatype and format
 *
 * @private
 * @returns {buffer}
 */
function generateSid () {
  const encodeLookup = '0123456789ABCDEF'
  const decodeLookup = []
  let j = 0
  while (j < 10) decodeLookup[0x30 + j] = j++
  while (j < 16) decodeLookup[0x61 - 10 + j] = j++

  let rawSid = '010500000000000515000000'
  for (let i = 0; i < 28; i++) {
    rawSid += encodeLookup.charAt(
      Math.floor(Math.random() * encodeLookup.length)
    )
  }
  rawSid = rawSid + '0000'

  const sizeof = rawSid.length >> 1
  const length = sizeof << 1
  const array = new Uint8Array(sizeof)
  let n = 0
  let i = 0
  while (i < length) {
    array[n++] =
      (decodeLookup[rawSid.charCodeAt(i++)] << 4) |
      decodeLookup[rawSid.charCodeAt(i++)]
  }
  return Buffer.from(array)
}

module.exports = {
  generateSid
}
