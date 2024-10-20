sudo apt update
sudo apt upgrade
sudo apt-get install libssl-dev
sleep 3
gcc -o decrypt_rsa decrypt_rsa.c -lssl -lcrypto 
gcc -o rsa_example rsa_example.c -lssl -lcrypto
sudo cp ./rsa_example /usr/bin
sudo cp ./decrypt_rsa /usr/bin
