#pragma once

#define ROUNDS 20
#define BLOCK_SIZE 64

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (                \
    a += b,  d ^= a,  d = ROTL(d,16),   \
    c += d,  b ^= c,  b = ROTL(b,12),   \
    a += b,  d ^= a,  d = ROTL(d, 8),   \
    c += d,  b ^= c,  b = ROTL(b, 7))

#ifdef _KERNEL_MODE
namespace std
{
    // STRUCT TEMPLATE remove_reference
    template <class _Ty>
    struct remove_reference {
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_reference<_Ty&> {
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_reference<_Ty&&> {
        using type = _Ty;
    };

    template <class _Ty>
    using remove_reference_t = typename remove_reference<_Ty>::type;

    // STRUCT TEMPLATE remove_const
    template <class _Ty>
    struct remove_const { // remove top-level const qualifier
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_const<const _Ty> {
        using type = _Ty;
    };

    template <class _Ty>
    using remove_const_t = typename remove_const<_Ty>::type;
}
#else
#include <type_traits>
#endif

namespace cha
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    template <int _size, wchar_t _key1, wchar_t _key2, typename T>
    class ChaChan
    {
    public:
        __forceinline constexpr ChaChan(T* data)
        {
            crypt(data);
        }

        __forceinline T* get()
        {
            return _storage;
        }

        __forceinline int size() // (w)char count
        {
            return _size;
        }

        __forceinline  wchar_t key()
        {
            return _key1;
        }

        __forceinline  T* encrypt()
        {
            if (!isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline  T* decrypt()
        {
            if (isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline bool isEncrypted()
        {
            return _storage[_size - 1] != 0;
        }

        __forceinline void clear() // set full storage to 0
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = 0;
            }
        }

        __forceinline operator T* ()
        {
            decrypt();

            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            unsigned int block[16]{}, x[16]{}, key[8]{}, nonce[3]{};
            unsigned int counter = 1;
            size_t i = 0, j = 0, k = 0;

            key[0] = _key1;
            key[1] = _key2;
            for (i = 2; i < 8; i++)
                key[i] = (48271 * i + (__TIME__[7] - '0')) % 2147483647;

            for (i = 0; i < 3; i++)
                nonce[i] = (48271 * i) % 2147483647;

            for (i = 0; i < _size; i += BLOCK_SIZE) {
                block[0] = 0x61707865;
                block[1] = 0x3320646e;
                block[2] = 0x79622d32;
                block[3] = 0x6b206574;
                for (j = 0; j < 8; j++)
                    block[j+4] = key[j];
                block[12] = counter;
                for (j = 0; j < 3; j++)
                    block[j+13] = nonce[j];

                for (j = 0; j < 16; ++j)
                    x[j] = block[j];

                for (j = 0; j < ROUNDS; j += 2) {
                    // Odd round
                    QR(x[0], x[4], x[ 8], x[12]); // column 0
                    QR(x[1], x[5], x[ 9], x[13]); // column 1
                    QR(x[2], x[6], x[10], x[14]); // column 2
                    QR(x[3], x[7], x[11], x[15]); // column 3
                    // Even round
                    QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
                    QR(x[1], x[6], x[11], x[12]); // diagonal 2
                    QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
                    QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
                }

                for (j = 0; j < 16; ++j)
                    block[j] = (x[j] + block[j]) & 0xffffffff;

                unsigned char block_bytes[BLOCK_SIZE]{};
                for (k = 0; k < 16; ++k) {
                    block_bytes[k * 4 + 0] = (block[k] >> 0) & 0xFF;
                    block_bytes[k * 4 + 1] = (block[k] >> 8) & 0xFF;
                    block_bytes[k * 4 + 2] = (block[k] >> 16) & 0xFF;
                    block_bytes[k * 4 + 3] = (block[k] >> 24) & 0xFF;
                }

                size_t block_size = (_size - i < 64) ? (_size - i) : 64;
                for (j = 0; j < block_size; ++j)
                    _storage[i + j] = data[i + j] ^ block_bytes[j];

                counter++;
            }
        }

        T _storage[_size]{};
    };
}

#define strcha(str) strcha_key(str, __TIME__[4], __TIME__[6])
#define strcha_key(str, key1, key2) []() { \
            constexpr static auto crypted = cha::ChaChan \
                <sizeof(str) / sizeof(str[0]), key1, key2, cha::clean_type<decltype(str[0])>>((cha::clean_type<decltype(str[0])>*)str); \
                    return crypted; }()

/*____________________________________________________________________________________________________________
Original Author: skadro
Github: https://github.com/skadro-official
License: See end of file
skCrypter
		Compile-time, Usermode + Kernelmode, safe and lightweight string crypter library for C++11+
							*Not removing this part is appreciated*
____________________________________________________________________________________________________________*/

/*________________________________________________________________________________
MIT License
Copyright (c) 2020 skadro
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
________________________________________________________________________________*/
