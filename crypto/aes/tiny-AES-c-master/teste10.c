#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"  

static void text_to_hex(const char *text, uint8_t *output, size_t offset);
static void phex(uint8_t* str, size_t len);
static void test_encrypt_ecb(void);
static void test_decrypt_ecb(uint8_t *in, size_t len);

int main(void)
{
    uint8_t len; // Tamanho em bytes a ser utilizado na chave  

#if defined(AES256)
    printf("\nTesting AES256\n\n");
    len = 32;  // Tamanho da chave para AES256
#elif defined(AES192)
    printf("\nTesting AES192\n\n");
    len = 24;  // Tamanho da chave para AES192
#elif defined(AES128)
    printf("\nTesting AES128\n\n");
    len = 16;  // Tamanho da chave para AES128
#else
    printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting\n");
    return 0;
#endif

    printf("The key length is: %d bytes\n", len);  // Exibe o tamanho da chave
    printf("\n");

    // Chama a função de teste de criptografia
    test_encrypt_ecb();

    return 0;
}

static void text_to_hex(const char *text, uint8_t *output, size_t offset)
{
    size_t len = strlen(text);
    size_t i;

    // A condição offset + i impede a leitura de uma string inválida
    // Se o texto tiver 10 caracteres eu trunco o primeiro for para não ler informações inválidas

    for (i = 0; i < 16 && (offset + i) < len; ++i) {
        output[i] = (uint8_t) text[offset + i];
    }

    // O restante da informação é preenchido nesse for
    for (; i < 16; ++i) {
        output[i] = 0x00;
    }
}

static void phex(uint8_t* str, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%.2x", str[i]);
    }
    printf("\n");
}

static void test_encrypt_ecb(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }; // Definição da chave a ser utilizada para criptografia
    const char *text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"; // Definição da mensagem a ser criptografada
    
    uint8_t plain_text[16]; // Alocação de blocos de 16 bytes para serem criptografados
    uint8_t encrypted_text[16 * 10];  // Aloca mais espaço para os dados criptografados
    size_t offset = 0;
    size_t encrypted_offset = 0;

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    printf("Original plain text: %s\n\n", text);

    printf("Plain text (hexadecimal):\n");
    while (offset < strlen(text)) {
        text_to_hex(text, plain_text, offset);
        phex(plain_text, 16);
        offset += 16;
    }

    // Criptografa o texto
    offset = 0;
    printf("\nEncrypted text (hexadecimal):\n");
    while (offset < strlen(text)) {
        text_to_hex(text, plain_text, offset);
        AES_ECB_encrypt(&ctx, plain_text);
        memcpy(&encrypted_text[encrypted_offset], plain_text, 16);
        encrypted_offset += 16;
        phex(plain_text, 16);
        offset += 16;
    }

    // Agora, criptografa o texto original e passa o resultado para a descriptografia
    printf("\nDecrypting the encrypted text:\n");
    test_decrypt_ecb(encrypted_text, encrypted_offset);
}

static void test_decrypt_ecb(uint8_t *in, size_t len)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }; // Definição da chave para decriptografia
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    printf("Decrypted text (hexadecimal):\n");
    for (size_t i = 0; i < len; i += 16) {
        AES_ECB_decrypt(&ctx, &in[i]);
        phex(&in[i], 16);  // Exibe o texto descriptografado em hexadecimal
    }

    printf("\nDecrypted text: ");
    for (size_t i = 0; i < len; ++i) {
        if (in[i] != 0x00) {  // Ignora o padding
            printf("%c", in[i]);
        }
    }
    printf("\n");
}
