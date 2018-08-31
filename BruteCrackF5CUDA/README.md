
requires NVidia GPU and CUDA toolkit

build on linux
nvcc kernel.cu -o F5CUDA

on windows you need visual studio and cuda tools
also need to set tdrDelay if you are using display video card
Go to "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" and create a key of type "DWORD (32-bit)" and name "TdrDelay" with a value of 10 as Decimal value.

the number of blocks you can use depends on the size of the file and the amount of memory on GPU
more is faster, multiples of 32

F5CUDA.exe --blocks 32 -p passwords.txt Q4Example.jpg.coeff

options

--pass FILENAME Password list. Expected to be seperated by new-line charactors
--gpu number
--blocks count
keep trying higher block until you get out of memory errors
--threads count
8 seems fastest
--max-pass max length of password
--max-decode max number of bytes matching PixelKnot header to decode
--skip skip lines of password file
--suffix try all suffix of each password up to length

pixelknot uses the last 1/3 of the password for the f5 layer so suffix will try all the suffixes of the passwords 
to try all 8-3 letter suffixes in a file

