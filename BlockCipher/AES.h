#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <string>
#include <iostream>
using namespace std;
using namespace CryptoPP;
class Aes_class
{
private:
    string fin;
    string fout;
    string pass;
    string IV;
    string salt = "solyanka";
public:
    Aes_class() = delete;
    Aes_class(const string& fin, const string& fout, const string& pass);
    Aes_class(const string& fin, const string& fout, const string& pass, const string & IV);
    void encryptAES (Aes_class encr);
    void decryptAES (Aes_class decr);

};
