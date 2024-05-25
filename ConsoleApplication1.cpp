#include <iostream>
#include <chrono>

#include "LuciferCipher.h"

using namespace std;

int main()
{
    setlocale(0, "");
    std::chrono::high_resolution_clock::time_point timeStart;
    std::chrono::high_resolution_clock::time_point timeEnd;
    long long timeElapsed;

    LuciferCipher cipher;
    const int numRounds = 1; // Количество раундов

    // Пример использования
    string text = "Основы ИБ крутой предмет, лучший курс, много узнали. Устали!!! ";
    string key = "0123456789abcdef0123456789abcdef"; // 128-битный ключ

    timeStart = std::chrono::high_resolution_clock::now();
    string encryptResult = cipher.encrypt(text, key, numRounds);
    timeEnd = std::chrono::high_resolution_clock::now();

    timeElapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(timeEnd - timeStart).count();
    cout << "Time for encryption: " << timeElapsed << " ns" << endl;

    timeStart = std::chrono::high_resolution_clock::now();
    string decryptResult = cipher.decrypt(encryptResult, key, numRounds);
    timeEnd = std::chrono::high_resolution_clock::now();

    timeElapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(timeEnd - timeStart).count();
    cout << "Time for decryption: " << timeElapsed << " ns" << endl;

    cout << text << endl;
    cout << encryptResult << endl;
    cout << decryptResult << endl;
}
