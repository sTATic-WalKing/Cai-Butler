gcc -fPIC -c \
-I /home/cai/openssl/include -L /home/cai/openssl -l crypto -l ssl \
rsa.c

ar -crv rsa.a rsa.o

gcc -fPIC -shared -o librsa.so -Wl,--whole-archive rsa.a /home/cai/openssl/libcrypto.a /home/cai/openssl/libssl.a -Wl,--no-whole-archive