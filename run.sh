gcc main.c -o bin/kc
gcc interp.c -o bin/kdc
cd bin
./kc ../examples/main.k
./main
echo "Returned" $?