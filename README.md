# TLS
Implements a simplified TLS protocol in Java, focusing on secure communication using RSA, AES-CBC, HMAC, and Diffie-Hellman key exchange.

The steps to complete a secure handshake are implemented and ran as shown below. 

![TLS](https://github.com/SarahBateman22/TLS/assets/142822160/c045cee5-4b8b-4e1f-875c-70de0de5b2a9)
Step 1 (yellow): SERVER: Receives and stores the nonce (number used once) from the client.
                 CLIENT: Sends the nonce.
                 
Step 2 (purple): SERVER: Sends server's certificate, serverDHPub, and signed Diffie-Hellman public key.
                 CLIENT: Receives the handshake files from the server and validates the server's certificate (blue).
                 
Step 3 (light pink): SERVER: Receives the handshake files from the client and validates the client's certificate (blue).
                     CLIENT: Sends client's certificate, clientDHPub, and signed Diffie-Hellman public key.

Step 4 (green): SERVER AND CLIENT: Generate shared Diffie-Hellman secret key, then generate secure keysets using the shared secret key.

Step 5 (white): SERVER: Send HMAC (Hash-Based Message Authentication Code) message of all handshake messages so far using the server's MAC key.
                CLIENT: Receive summary message from the server and validate (orange) that the client message history is the same.

Step 6 (white): SERVER: Receive summary message from the client and validate (orange) that the server message history is the same.
                CLIENT: Send HMAC (Hash-Based Message Authentication Code) message of all handshake messages so far using the client's MAC key


At this point the handshake is complete and the server and client can send secure messages to each other. When encrypting and decrypting messages, there is also a verification that the messages have not been altered anywhere (dark pink).
