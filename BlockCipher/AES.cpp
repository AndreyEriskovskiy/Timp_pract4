#include "AES.h"
Aes_class::Aes_class(const string& fin, const string& fout, const string& pass)
{
    this->fin=fin;
    this->fout=fout;
    this->pass=pass;
}

Aes_class::Aes_class(const string& fin, const string& fout, const string& pass, const string& IV)
{
    this->fin=fin;
    this->fout=fout;
    this->pass=pass;
    this->IV=IV;
}

void Aes_class::encryptAES(Aes_class encr)
{
    // Генерация ключа из пароля
    SecByteBlock key (AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)encr.pass.data(), encr.pass.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    // Генерация вектора инициализации
    AutoSeededRandomPool init;
    byte iv[AES::BLOCKSIZE];
    init.GenerateBlock(iv, sizeof(iv));
    
    ofstream write_iv(string(encr.fout+".iv").c_str(), ios::out | ios::binary);
    write_iv.write((char*)iv, AES::BLOCKSIZE);
    write_iv.close();
    cout<<"Был сгенерирован вектор инициализации и помещён в файл -> "<<encr.fout<<".iv"<<endl;
    
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource s(encr.fin.c_str(), true, new StreamTransformationFilter(enc, new FileSink(encr.fout.c_str())));
    cout <<"Зашифрованное сообщение было успешно записано в файл. Результат находится в файле по следующему пути -> "<<encr.fout << endl;
}
void Aes_class::decryptAES(Aes_class decr)
{
    SecByteBlock key (AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)decr.pass.data(), pass.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    byte iv[AES::BLOCKSIZE];
    ifstream write_iv(decr.IV.c_str(), ios::in | ios::binary);
    if(!write_iv) {
        throw string("Ошибка открытия файла");
        write_iv.close();
    }
    else if(write_iv.good()) {
        write_iv.read((char*)(&iv), AES::BLOCKSIZE);
        write_iv.close();
    }

    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(decr.fin.c_str(), true, new StreamTransformationFilter(dec, new FileSink(decr.fout.c_str())));
    cout << "Расшифрованное сообщение было успешно записано в файл. Результат находится в файле по следующему пути -> " << decr.fout << endl;

}
