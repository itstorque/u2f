import sys

print("Usage: python3 include_key_cert.py [key.pem] [cert.der]")

buf_key  = bytearray(open(sys.argv[1], 'rb').read())
buf_cert = bytearray(open(sys.argv[2], 'rb').read())

data_key  = ''.join( map(lambda c:'\\x%02x'%c, buf_key ) )
data_cert = ''.join( map(lambda c:'\\x%02x'%c, buf_cert) )

data_key  = '\n'.join( [ "\"" + data_key[i:i+80] + "\"" for i in range(0, 4*len(buf_key), 80) ] )
data_cert = '\n'.join( [ "\"" + data_cert[i:i+80] + "\"" for i in range(0, 4*len(buf_cert), 80) ] )

print("const char attestation_key[] = " + data_key, end=";\n\n")
print("const char attestation_DER_cert[] = " + data_cert, end=";\n")
