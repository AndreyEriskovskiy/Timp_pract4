#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/rc6.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <string>
#include <iostream>
using namespace std;
using namespace CryptoPP;
class RC6_class
{
private:
    string fin;
    string fout; 
    string IV;
    string pass;
    string salt="solyanka";
public:
    RC6_class()=delete;
    RC6_class(const string& fin, const string& fout, const string& pass);
    RC6_class(const string& fin, const string& fout, const string& pass, const string& IV);
    void encryptRC6 (RC6_class encr);
    void decryptRC6 (RC6_class decr);

};
