# TLS
Implements a simplified TLS protocol in Java, focusing on secure communication using RSA, AES-CBC, HMAC, and Diffie-Hellman key exchange.

The steps to complete a secure handshake are implemented and ran as shown below. 

![TLS](https://github.com/SarahBateman22/TLS/assets/142822160/c045cee5-4b8b-4e1f-875c-70de0de5b2a9)
Step 1 (yellow): SERVER: Receives and stores the nonce (number used once) from the client.
                 CLIENT: Sends the nonce.
                 
Step 2 (purple): SERVER: Sends server's certificate, serverDHPub, and signed Diffie-Hellman public key.
                 CLIENT: Receives the handshake files from the server and validates the server's certificate (blue).
                 
Step 3 (light pink): 
