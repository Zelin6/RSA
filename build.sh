sudo apt-get install libssl-dev
sleep 3
gcc -o decrypt_rsa decrypt_rsa.c -lssl -lcrypto 
gcc -o rsa_example rsa_example.c -lssl -lcrypto
