gcc main.c -o bin/kc
gcc interp.c -o bin/kdc
cd code
kc main.k
./main
echo "Returned" $?