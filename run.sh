gcc main.c -o bin/kc
gcc interp.c -o bin/kdc
cd code
kc main.k -byte
kdc a.ke
echo "Returned" $?