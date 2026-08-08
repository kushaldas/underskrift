#!/usr/bin/env python3
"""DER navigation for the end-to-end CMS checks.

Deliberately does no cryptography: it only locates bytes inside a SignedData so
that openssl can do the arithmetic on them. Keeping the two apart is the point —
a check is only independent if our code is not the one computing the answer.

Subcommands:
  count <cms>                     number of SignerInfos
  signature <cms> <i> <out>       write signer i's signature value to <out>
  countersig-digest <cms> <i>     print the messageDigest of the countersignature
                                  attached to signer i (hex)
  break-signer <cms> <out> <i>    flip a byte inside signer i's signature
"""

import sys

OID_COUNTERSIGNATURE = bytes.fromhex("06092A864886F70D010906")
OID_MESSAGE_DIGEST = bytes.fromhex("06092A864886F70D010904")


def read_tlv(data, off):
    """Return (tag, value_start, value_end) for the TLV at off."""
    tag = data[off]
    first = data[off + 1]
    if first < 0x80:
        length, header = first, 2
    else:
        n = first & 0x7F
        length = int.from_bytes(data[off + 2 : off + 2 + n], "big")
        header = 2 + n
    start = off + header
    return tag, start, start + length


def children(data, start, end):
    """Return [(tag, tlv_start, value_start, value_end)] for a constructed value."""
    out = []
    pos = start
    while pos < end:
        tag, vstart, vend = read_tlv(data, pos)
        out.append((tag, pos, vstart, vend))
        pos = vend
    return out


def signer_infos(data):
    _, ci_start, ci_end = read_tlv(data, 0)
    content = children(data, ci_start, ci_end)[1]        # [0] EXPLICIT content
    _, sd_start, sd_end = read_tlv(data, content[2])     # SignedData SEQUENCE
    sd_fields = children(data, sd_start, sd_end)
    # digestAlgorithms is also a SET; signerInfos is the last one.
    infos = [f for f in sd_fields if f[0] == 0x31][-1]
    return children(data, infos[2], infos[3])


def signer(data, index):
    infos = signer_infos(data)
    if index >= len(infos):
        sys.exit(f"only {len(infos)} SignerInfo(s) present")
    tag, start, end = read_tlv(data, infos[index][1])
    return children(data, start, end)


def find_attribute(data, attrs_start, attrs_end, oid):
    """Value of the attribute with the given OID, as (value_start, value_end)."""
    for _, attr_start, attr_vstart, attr_vend in children(data, attrs_start, attrs_end):
        fields = children(data, attr_vstart, attr_vend)
        oid_field = fields[0]
        if data[oid_field[1] : oid_field[3]] == oid:
            values = children(data, fields[1][2], fields[1][3])
            return values[0][1], values[0][3]
    return None


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    command, path = sys.argv[1], sys.argv[2]
    data = bytearray(open(path, "rb").read())

    if command == "count":
        print(len(signer_infos(data)))

    elif command == "signature":
        index, out = int(sys.argv[3]), sys.argv[4]
        octets = [c for c in signer(data, index) if c[0] == 0x04]
        if not octets:
            sys.exit("no signature OCTET STRING in that SignerInfo")
        open(out, "wb").write(data[octets[0][2] : octets[0][3]])

    elif command == "countersig-digest":
        index = int(sys.argv[3])
        unsigned = [c for c in signer(data, index) if c[0] == 0xA1]
        if not unsigned:
            sys.exit("that SignerInfo has no unsigned attributes")
        found = find_attribute(data, unsigned[0][2], unsigned[0][3], OID_COUNTERSIGNATURE)
        if not found:
            sys.exit("no countersignature attribute")
        # The attribute value is a SignerInfo; reach into its signedAttrs.
        _, cs_start, cs_end = read_tlv(data, found[0])
        signed_attrs = [c for c in children(data, cs_start, cs_end) if c[0] == 0xA0]
        if not signed_attrs:
            sys.exit("the countersignature has no signed attributes")
        digest = find_attribute(data, signed_attrs[0][2], signed_attrs[0][3], OID_MESSAGE_DIGEST)
        if not digest:
            sys.exit("the countersignature has no messageDigest")
        _, dstart, dend = read_tlv(data, digest[0])
        print(data[dstart:dend].hex())

    elif command == "break-signer":
        out, index = sys.argv[3], int(sys.argv[4])
        octets = [c for c in signer(data, index) if c[0] == 0x04]
        if not octets:
            sys.exit("no signature OCTET STRING in that SignerInfo")
        data[octets[0][2]] ^= 0xFF
        open(out, "wb").write(data)

    else:
        sys.exit(f"unknown command: {command}")


if __name__ == "__main__":
    main()
