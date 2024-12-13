# TimeStamp

Repository with some code for timestamps according to RFC 3161 (Time Stamp Protocol

## Java (/examples/java)

#### PDFTimestampSignature (Main Class)

It will be necessary to change the values ​​of **[[CLIENT-ID]]** and **[[CLIENT-SECRET]]** for the TimeStamp API authentication credentials.

Other configuration parameters:

- urlAuthServer: URL authentication server
- urlTimeStampApi: URL TimeStamp API
- fileToSign: File path to be stamped
- apiType: JSON ou ASN1 (TSR - TimeStamp Request)
- hashAlgorithm: SHA-256 ou SHA-512
