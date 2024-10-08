#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include "aes.h"

int main(int argc, char *argv[])
{
    // Garantir suporte a UTF-8
    setlocale(LC_ALL, "pt_BR.UTF-8");

    // Definições de tamanho
    int expandedKeySize = 176;
    enum keySize size = SIZE_16;

    // Chave e outros vetores
    unsigned char expandedKey[expandedKeySize];
    unsigned char key[16];
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    // Chaves e texto plano em HEX
    const char *hex_key = "0f1571c947d9e8590cb7add6af7f6798";
    const char *hex_plain_text = "0123456789abcdeffedcba9876543210";

    // Converter chave e plaintext de hexadecimal para bytes
    hexStringToBytes(hex_key, key, 16);
    hexStringToBytes(hex_plain_text, plaintext, 16);

    printf("\nChave cifrada (HEX):\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x", key[i]);
    }
    printf("\n");

    // Expandir a chave
    expandKey(expandedKey, key, size, expandedKeySize);

    printf("\nChave expandida (HEX):\n");
    for (int i = 0; i < expandedKeySize; i++)
    {
        printf("%2.2x%c", expandedKey[i], ((i + 1) % 16) ? ' ' : '\n');
    }

    printf("\nTexto plano (HEX):\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x", plaintext[i]);
    }
    printf("\n");

    aes_encrypt(plaintext, ciphertext, key, SIZE_16);

    printf("\nTexto cifrado (HEX):\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x", ciphertext[i]);
    }
    printf("\n");

    // Descriptografar o texto cifrado
    aes_decrypt(ciphertext, decryptedtext, key, SIZE_16);

    printf("\nTexto descriptografado (HEX):\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x", decryptedtext[i]);
    }
    printf("\n");

    return 0;
}

// Transforma strings HEX em bytes
void hexStringToBytes(const char *hexString, unsigned char *byteArray, int byteArraySize)
{
    for (int i = 0; i < byteArraySize; i++)
    {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

// Getter da S-BOX
unsigned char getSBoxValue(unsigned char num)
{
    return sbox[num];
}

// Getter da S-BOX invertida
unsigned char getSBoxInvert(unsigned char num)
{
    return rsbox[num];
}

/* Rotaciona a palavra 8 bits para à esquerda
 * exemplo> rotate(1d2c3a4f) = 2c3a4f1d
 * 
 * word = char[4] (32 bit)
 */
void rotate(unsigned char *word)
{
    unsigned char c;
    int i;

    c = word[0];
    for (i = 0; i < 3; i++)
        word[i] = word[i + 1];

    word[3] = c;
}

// Getter da tabela de R-CON
unsigned char getRconValue(unsigned char num)
{
    return Rcon[num];
}

void core(unsigned char *word, int iteration)
{
    int i;

    rotate(word);

    // Aplica a substituição
    for (i = 0; i < 4; ++i)
    {
        word[i] = getSBoxValue(word[i]);
    }

    // Realiza uma operação XOR com o output do RCON
    word[0] = word[0] ^ getRconValue(iteration);
}

// Expande uma chave de 128,192,256 bytes em outra de 176,208,240 bytes
void expandKey(unsigned char *expandedKey,
               unsigned char *key,
               enum keySize size,
               size_t expandedKeySize)
{
    // Tamanho da chave expandida
    int currentSize = 0;
    int rconIteration = 1;
    int i;
    unsigned char t[4] = {0}; // Temp

    // Define os 16,24,32 bytes da chave expandida para a chave de entrada
    for (i = 0; i < size; i++)
        expandedKey[i] = key[i];

    currentSize += size;

    while (currentSize < expandedKeySize)
    {
        // Atribui os 4 bytes anteriores a variável temp
        for (i = 0; i < 4; i++)
        {
            t[i] = expandedKey[(currentSize - 4) + i];
        }

        // A cada 16,24,32 bytes, aplica para a iteração para temp do RCON+1
        if (currentSize % size == 0)
        {
            core(t, rconIteration++);
        }

        // Para chaves de 256 bits, é adicionado uma S-BOX extra
        if (size == SIZE_32 && ((currentSize % size) == 16))
        {
            for (i = 0; i < 4; i++)
                t[i] = getSBoxValue(t[i]);
        }

        /* Faz o XOR com t com o bloco de quatro bytes, 16,24,32 bytes antes da nova chave expandida.
         * que vira os próximos quatro bytes na chave expandida.
         */
        for (i = 0; i < 4; i++)
        {
            expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[i];
            currentSize++;
        }
    }
}

void subBytes(unsigned char *state)
{
    int i;

    /*
     * Substitui todos os valores do estado com o valor no S-BOX
     * usando o valor do estado como índice para o S-BOX
     */
    for (i = 0; i < 16; i++)
        state[i] = getSBoxValue(state[i]);
}

void shiftRows(unsigned char *state)
{
    int i;

    // Itera sobre as 4 linhas e as troca com essa linha
    for (i = 0; i < 4; i++)
        shiftRow(state + i * 4, i);
}

void shiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;

    // Cada iteração desloca a linha para a esquerda em 1
    for (i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}

void addRoundKey(unsigned char *state, unsigned char *roundKey)
{
    int i;

    // Faz um XOR do estado atual com a roundKey
    for (i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}

unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;

    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;

        hi_bit_set = (a & 0x80);
        a <<= 1;

        if (hi_bit_set == 0x80)
            a ^= 0x1b;

        b >>= 1;
    }

    return p;
}

void mixColumns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    // Itera as 4 colunas
    for (i = 0; i < 4; i++)
    {
        // Constrói uma coluna iterando sobre as 4 linhas
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }

        // Faz o mix da coluna
        mixColumn(column);

        // Retorna os valores da coluna para o estado
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}

void mixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;

    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }

    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}

void aes_round(unsigned char *state, unsigned char *roundKey)
{
    printf("\nChave da rodada:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }

    printf("\nEstado inicial:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }

    subBytes(state);
    printf("\nApós SubBytes:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }

    shiftRows(state);
    printf("\nApós ShiftRows:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }

    mixColumns(state);
    printf("\nApós MixColumns:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }

    addRoundKey(state, roundKey);
    printf("\nApós a RoundKey:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%2.2x%c", state[i], ((i + 1) % 4) ? ' ' : '\n');
    }
}

void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey)
{
    int i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            roundKey[(i + (j * 4))] = expandedKey[(i * 4) + j];
    }
}

void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{
    int i = 0;

    unsigned char roundKey[16];

    createRoundKey(expandedKey, roundKey);
    addRoundKey(state, roundKey);

    for (i = 1; i < nbrRounds; i++)
    {
        printf("\n========Rodada %d========\n", i);
        createRoundKey(expandedKey + 16 * i, roundKey);
        aes_round(state, roundKey);
        printf("\n========Fim da rodada %d========\n", i);
    }

    createRoundKey(expandedKey + 16 * nbrRounds, roundKey);
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKey);
}

char aes_encrypt_hex(const char *hexInput,
                     const char *hexKey,
                     unsigned char *output,
                     enum keySize size)
{
    // O texto e a chave são strings hexadecimais, então são convertidas para bytes

    unsigned char input[16]; // 128 bits = 16 bytes
    unsigned char key[32];   // 256 bits = 32 bytes (máximo)

    // Converter texto plano de hex para bytes
    hexStringToBytes(hexInput, input, 16);

    // Converter chave de hex para bytes
    hexStringToBytes(hexKey, key, size);

    // Agora chamar a função original com os inputs em bytes
    return aes_encrypt(input, output, key, size);
}

char aes_encrypt(unsigned char *input,
                 unsigned char *output,
                 unsigned char *key,
                 enum keySize size)
{
    int expandedKeySize;
    int nbrRounds;
    unsigned char *expandedKey;
    unsigned char block[16];
    int i, j;

    switch (size)
    {
    case SIZE_16:
        nbrRounds = 10;
        break;
    case SIZE_24:
        nbrRounds = 12;
        break;
    case SIZE_32:
        nbrRounds = 14;
        break;
    default:
        return ERROR_AES_UNKNOWN_KEYSIZE;
        break;
    }

    expandedKeySize = (16 * (nbrRounds + 1));
    expandedKey = (unsigned char *)malloc(expandedKeySize * sizeof(unsigned char));

    if (expandedKey == NULL)
    {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        /* Defina os valores do bloco para o bloco:
         * a0,0 a0,1 a0,2 a0,3
         * a1,0 a1,1 a1,2 a1,3
         * a2,0 a2,1 a2,2 a2,3
         * a3,0 a3,1 a3,2 a3,3
         * a ordem de mapeamento é: a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
         */

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
                block[(i + (j * 4))] = input[(i * 4) + j];
        }

        expandKey(expandedKey, key, size, expandedKeySize);

        aes_main(block, expandedKey, nbrRounds);

        // Desmapeia o bloco novamente
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
                output[(i * 4) + j] = block[(i + (j * 4))];
        }

        free(expandedKey);
        expandedKey = NULL;
    }

    return SUCCESS;
}

void invSubBytes(unsigned char *state)
{
    int i;

    // Substitui todos os valores do estado com o valor do S-BOX invertido
    for (i = 0; i < 16; i++)
        state[i] = getSBoxInvert(state[i]);
}

void invShiftRows(unsigned char *state)
{
    int i;

    // Troca a linha do estado baseado na S-BOX invertida
    for (i = 0; i < 4; i++)
        invShiftRow(state + i * 4, i);
}

void invShiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;

    // Cada iteração desloca a linha para a direita em 1
    for (i = 0; i < nbr; i++)
    {
        tmp = state[3];
        for (j = 3; j > 0; j--)
            state[j] = state[j - 1];

        state[0] = tmp;
    }
}

void invMixColumns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }

        // Faz o mix reverso na coluna
        invMixColumn(column);

        // Joga os valores no estado
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}

void invMixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;

    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }

    column[0] = galois_multiplication(cpy[0], 14) ^
                galois_multiplication(cpy[3], 9) ^
                galois_multiplication(cpy[2], 13) ^
                galois_multiplication(cpy[1], 11);
    column[1] = galois_multiplication(cpy[1], 14) ^
                galois_multiplication(cpy[0], 9) ^
                galois_multiplication(cpy[3], 13) ^
                galois_multiplication(cpy[2], 11);
    column[2] = galois_multiplication(cpy[2], 14) ^
                galois_multiplication(cpy[1], 9) ^
                galois_multiplication(cpy[0], 13) ^
                galois_multiplication(cpy[3], 11);
    column[3] = galois_multiplication(cpy[3], 14) ^
                galois_multiplication(cpy[2], 9) ^
                galois_multiplication(cpy[1], 13) ^
                galois_multiplication(cpy[0], 11);
}

void aes_invRound(unsigned char *state, unsigned char *roundKey)
{

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKey);
    invMixColumns(state);
}

void aes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{
    int i = 0;

    unsigned char roundKey[16];

    createRoundKey(expandedKey + 16 * nbrRounds, roundKey);
    addRoundKey(state, roundKey);

    for (i = nbrRounds - 1; i > 0; i--)
    {
        createRoundKey(expandedKey + 16 * i, roundKey);
        aes_invRound(state, roundKey);
    }

    createRoundKey(expandedKey, roundKey);
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKey);
}

char aes_decrypt(unsigned char *input,
                 unsigned char *output,
                 unsigned char *key,
                 enum keySize size)
{
    int expandedKeySize;
    int nbrRounds;
    unsigned char *expandedKey;
    unsigned char block[16];
    int i, j;

    switch (size)
    {
    case SIZE_16:
        nbrRounds = 10;
        break;
    case SIZE_24:
        nbrRounds = 12;
        break;
    case SIZE_32:
        nbrRounds = 14;
        break;
    default:
        return ERROR_AES_UNKNOWN_KEYSIZE;
        break;
    }

    expandedKeySize = (16 * (nbrRounds + 1));
    expandedKey = (unsigned char *)malloc(expandedKeySize * sizeof(unsigned char));

    if (expandedKey == NULL)
    {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
                block[(i + (j * 4))] = input[(i * 4) + j];
        }

        expandKey(expandedKey, key, size, expandedKeySize);

        aes_invMain(block, expandedKey, nbrRounds);

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
                output[(i * 4) + j] = block[(i + (j * 4))];
        }

        free(expandedKey);
        expandedKey = NULL;
    }

    return SUCCESS;
}