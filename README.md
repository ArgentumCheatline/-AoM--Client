## AO-Modding (Client)

AoM-Client is the client implementation of the modding platform for Argentum Online.
AoM-Client act like a proxy between the client and the server, deferring all messages unencrypted
between to AoM-Server.

## Protocol

NOTE: All bytes are encoded using network endian (Big Endian).

BYTE 1        | SHORT 2-3       | BYTES (4-n)
------------- | --------------- | -------------
ID = 0x00 (C) | Data Length     | Data
ID = 0x01 (S) | Data Length     | Data


## Client Supported

NAME          | SITE            | DATE
------------- | --------------- | -------------
MainAO        | [Link](http://www.comunidadargentum.com)     | 6/1/2015 (Full)
FuriusAO      | [Link](http://www.furiusao.com.ar)           | 6/1/2015 (Full)

## How to Build

Requires Visual Studio (Environment) tools and CMake.

```
cd client/<Name>
mkdir build
cd build
cmake -G "NMake Makefiles" ..
nmake
```