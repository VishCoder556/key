gcc main.c -o bin/kc
cd code
kc main.k
./main
echo "Returned" $?