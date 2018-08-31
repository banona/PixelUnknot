This is a program to rapidly test passwords against a F5 or PixelKnot image.

1. Compile the java blob:
    javac ExtractCoeff.java
2. Extract the coefficients from a jpeg image. (TODO: build this in)
    java ExtractCoeff test.jpg test.coeff
3. Compile the C code
    ./compile_me
    (runs 'gcc -O3 *.c -o brutecrackF5 -lpthread' )
4. Acquire a long list of possible passwords. I leave you to your own devices.
5. Test
    ./brutecrackF5 test.coeff --pass passwords.txt
