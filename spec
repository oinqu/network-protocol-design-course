Each node in update packet sends list of it's direct neighbors.

Update packet should contain version number that is increased on each issued update packet.

Node should store information about all nodes' direct neighbors and update packet version number, that contained this info.

Flooding:
	When node receives an update packet, it should forward it to all direct neighbors, except the one it was received from.
	If node receives update packet with version number smaller than latest stored version, node drops it.
	This should happen on the application layer not on the network layer,
	because the network layer does not have sufficient information to make forwarding decisions in this case.

Version number will get overflowed at some point, thus, update packet with version number significantly lower (exact number should be defined) than stored version number should be treated as a valid update packet.

If acknowledgement packet was not received in X seconds, packet is being sent again.

The PAYLOAD has a maximal length of 100 Bytes. Packets with larger payload must be segmented.

The PAYLOAD must be encrypted. Encryption should happen with the crypto scheme
proposed by libnacl[0]. Use the crypto_box function to encrypt
and the crypto_box_open function to decrypt, the names may slightly differ in different implementations.
The encrypted payload should be encoded with base64.
Consequently the payload must be decoded with base64 before decrypting it.
The public keys should be exchanged out of band.

Everyhing send over the network must contain only ASCII characters.


!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Note: Spaces around pipe symbols are for better visual representation and shoud not be present in actual packet that will be sent
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


Packet structure:
    SRC | DST | HOP_COUNT | SEGMENTATION_TYPE | SEGMENTATION_INFORMATION | PACKET_TYPE | PAYLOAD

PAYLOAD structure by message type:
    ROUTING:
        NODE | VERSION | NEIGHBOUR_COUNT | NEIGHBOUR_LIST
            NODE:
                Node name, to whom this packet belongs
            VERSION:
                maximum 5 characters
            NEIGHBOUR_COUNT:
                maximum 3 characters
            NEIGHBOUR_LIST:
                NODE_NAME & WEIGHT
    CHAT:
        MESSAGE_TYPE | CONTENT
            MESSAGE_TYPE:
                Possible values: FILE, MESSAGE
            CONTENT:
                In case of file: FILE_NAME&DATA
                In case of message: DATA


SEGMENTATION_INFORMATION structure by SEGMENTATION_TYPE:
    SEGMENT:
        MESSAGE_ID | SEGMENT | CHECKSUM
            MESSAGE_ID:
                Unique identifier that is common for all segments that add up into one single piece of data.
                Case sensitive.
            SEGMENT:
                segment_number/total_number_of_segments
                Example: 2/7 (2 out of 7)
            CHECKSUM:
                Checksum of the payload. The checksum must be generated with md5.
    ACK:
        MESSAGE_ID | SEGMENT
            Definitions are the same as in SEGMENT type, but with one main difference: PACKET ENDS HERE!


Examples:
    ROUTING:
        Furkan | Stas | 254 | SEGMENT | 1s6Ah79 | 1/1 | b52196356eba6a557db5b27fd11490f3 | ROUTING | Furkan | 387 | 2 | Olaf&2 | Stas&3

    CHAT:
        Furkan | Stas | 223 | SEGMENT | 1s6Ak96 | 1/2 | 228e0125567f82a757a660c123180108 | CHAT | FILE | data.txt&word1 word2 word3 word4 wo
        Furkan | Stas | 223 | SEGMENT | 1s6Ak96 | 2/2 | 462e825b7bf57d7c220c6a5f7f566e73 | CHAT | rd5 word6 word7 word8
    ACK:
        Stas | Furkan | 254 | ACK | 1s6Ak96 | 1/2
        Stas | Furkan | 254 | ACK | 1s6Ak96 | 2/2

    [0] original implementation: https://nacl.cr.yp.to/box.html
    python wrapper: https://libnacl.readthedocs.io/en/latest/topics/sealed.html#creating-box