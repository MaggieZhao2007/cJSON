#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "cJSON.h"

// ========== 加密配置（可根据需求调整） ==========
#define AES_KEY_SIZE 16  // AES-128 (16字节)
#define AES_IV_SIZE 16   // CBC 模式初始向量（IV）长度
#define PADDING_CHAR '\0'// 填充字符（AES要求明文长度为16的整数倍）

// ========== 辅助函数：数据填充（满足AES块长度要求） ==========
static char *padding_data(const char *data, size_t *out_len) {
    if (!data || !out_len) return NULL;
    
    size_t len = strlen(data);
    // 计算需要填充的长度
    size_t pad_len = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    if (pad_len == AES_BLOCK_SIZE) pad_len = 0;
    
    // 分配填充后的数据缓冲区
    size_t new_len = len + pad_len;
    char *padded = (char *)malloc(new_len + 1);
    if (!padded) return NULL;
    
    // 拷贝原始数据 + 填充
    memcpy(padded, data, len);
    memset(padded + len, PADDING_CHAR, pad_len);
    padded[new_len] = '\0';
    
    *out_len = new_len;
    return padded;
}

// ========== 辅助函数：去除填充数据 ==========
static char *unpadding_data(const char *data, size_t len) {
    if (!data || len == 0) return NULL;
    
    // 找到最后一个非填充字符的位置
    size_t real_len = len;
    while (real_len > 0 && data[real_len - 1] == PADDING_CHAR) {
        real_len--;
    }
    
    // 拷贝真实数据
    char *unpadded = (char *)malloc(real_len + 1);
    if (!unpadded) return NULL;
    memcpy(unpadded, data, real_len);
    unpadded[real_len] = '\0';
    
    return unpadded;
}

// ========== 核心：AES-CBC 加密/解密 ==========
/**
 * @brief AES-CBC 加密
 * @param plaintext 明文（JSON字符串）
 * @param key 加密密钥（16字节）
 * @param iv 初始向量（16字节，随机生成）
 * @param out_len 密文长度（输出）
 * @return 密文字符串（base64编码，便于传输），失败返回NULL
 */
static char *aes_cbc_encrypt(const char *plaintext, const unsigned char *key, 
                            unsigned char *iv, size_t *out_len) {
    if (!plaintext || !key || !iv || !out_len) return NULL;
    
    // 1. 数据填充
    size_t padded_len = 0;
    char *padded_data = padding_data(plaintext, &padded_len);
    if (!padded_data) return NULL;
    
    // 2. 初始化 AES 加密上下文
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        free(padded_data);
        return NULL;
    }
    
    // 3. 分配密文缓冲区（长度与填充后明文一致）
    unsigned char *ciphertext = (unsigned char *)malloc(padded_len);
    if (!ciphertext) {
        free(padded_data);
        return NULL;
    }
    
    // 4. 执行 AES-CBC 加密
    AES_cbc_encrypt((unsigned char *)padded_data, ciphertext, padded_len, 
                   &aes_key, iv, AES_ENCRYPT);
    
    // 5. Base64 编码（便于网络传输，避免二进制乱码）
    *out_len = EVP_EncodedLength(padded_len);
    char *base64_cipher = (char *)malloc(*out_len + 1);
    if (!base64_cipher) {
        free(ciphertext);
        free(padded_data);
        return NULL;
    }
    EVP_EncodeBlock((unsigned char *)base64_cipher, ciphertext, padded_len);
    base64_cipher[*out_len] = '\0';
    
    // 释放临时内存
    free(padded_data);
    free(ciphertext);
    return base64_cipher;
}

/**
 * @brief AES-CBC 解密
 * @param base64_cipher Base64编码的密文
 * @param key 解密密钥（与加密密钥一致）
 * @param iv 初始向量（与加密IV一致）
 * @param out_len 明文长度（输出）
 * @return 明文（JSON字符串），失败返回NULL
 */
static char *aes_cbc_decrypt(const char *base64_cipher, const unsigned char *key, 
                            unsigned char *iv, size_t *out_len) {
    if (!base64_cipher || !key || !iv || !out_len) return NULL;
    
    // 1. Base64 解码
    size_t cipher_len = EVP_DecodedLength(strlen(base64_cipher));
    unsigned char *ciphertext = (unsigned char *)malloc(cipher_len);
    if (!ciphertext) return NULL;
    
    int decoded_len = 0;
    if (EVP_DecodeBlock(ciphertext, (unsigned char *)base64_cipher, strlen(base64_cipher)) < 0) {
        free(ciphertext);
        return NULL;
    }
    
    // 2. 初始化 AES 解密上下文
    AES_KEY aes_key;
    if (AES_set_decrypt_key(key, 128, &aes_key) < 0) {
        free(ciphertext);
        return NULL;
    }
    
    // 3. 分配明文缓冲区
    unsigned char *plaintext = (unsigned char *)malloc(cipher_len);
    if (!plaintext) {
        free(ciphertext);
        return NULL;
    }
    
    // 4. 执行 AES-CBC 解密
    AES_cbc_encrypt(ciphertext, plaintext, cipher_len, &aes_key, iv, AES_DECRYPT);
    
    // 5. 去除填充
    char *unpadded_text = unpadding_data((char *)plaintext, cipher_len);
    *out_len = strlen(unpadded_text);
    
    // 释放临时内存
    free(ciphertext);
    free(plaintext);
    return unpadded_text;
}

// ========== cJSON 保密传输接口（对外暴露） ==========
/**
 * @brief 将 cJSON 节点加密为可传输的密文字符串
 * @param item cJSON 节点
 * @param key 加密密钥（必须16字节）
 * @param iv 输出初始向量（需保存，用于解密）
 * @return Base64编码的密文字符串，失败返回NULL
 */
char *cJSON_EncryptForTransmit(const cJSON *item, const unsigned char *key, unsigned char *iv) {
    if (!item || !key || !iv) return NULL;
    
    // 1. 将 cJSON 序列化为字符串
    char *json_str = cJSON_PrintUnformatted(item);
    if (!json_str) return NULL;
    
    // 2. 生成随机 IV（关键：每次加密IV不同，提升安全性）
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        free(json_str);
        return NULL;
    }
    
    // 3. AES 加密
    size_t cipher_len = 0;
    char *cipher_str = aes_cbc_encrypt(json_str, key, iv, &cipher_len);
    
    // 释放临时内存
    free(json_str);
    return cipher_str;
}

/**
 * @brief 将加密的字符串解密并解析为 cJSON 节点
 * @param cipher_str Base64编码的密文字符串
 * @param key 解密密钥（与加密密钥一致）
 * @param iv 加密时使用的初始向量
 * @return cJSON 节点，失败返回NULL
 */
cJSON *cJSON_DecryptFromTransmit(const char *cipher_str, const unsigned char *key, 
                                const unsigned char *iv) {
    if (!cipher_str || !key || !iv) return NULL;
    
    // 1. AES 解密
    size_t plain_len = 0;
    char *json_str = aes_cbc_decrypt(cipher_str, key, (unsigned char *)iv, &plain_len);
    if (!json_str) return NULL;
    
    // 2. 解析为 cJSON 节点
    cJSON *item = cJSON_Parse(json_str);
    
    // 释放临时内存
    free(json_str);
    return item;
}

// ========== 测试示例 ==========
int main() {
    // 1. 定义加密密钥（实际使用中需安全传输/存储，建议16字节随机值）
    const unsigned char secret_key[AES_KEY_SIZE] = "1234567890abcdef";
    unsigned char iv[AES_IV_SIZE] = {0};  // 存储随机IV
    
    // 2. 构建原始 JSON 数据
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "username", "admin");
    cJSON_AddStringToObject(root, "password", "123456");  // 敏感数据
    cJSON_AddNumberToObject(root, "balance", 10000.0);
    
    printf("原始 JSON 数据：\n%s\n\n", cJSON_PrintPretty(root));
    
    // 3. 加密（保密传输）
    char *cipher_str = cJSON_EncryptForTransmit(root, secret_key, iv);
    if (!cipher_str) {
        printf("加密失败！\n");
        cJSON_Delete(root);
        return 1;
    }
    printf("加密后的传输数据（Base64）：\n%s\n\n", cipher_str);
    
    // 4. 解密（接收端解析）
    cJSON *decrypted_root = cJSON_DecryptFromTransmit(cipher_str, secret_key, iv);
    if (!decrypted_root) {
        printf("解密失败！\n");
        free(cipher_str);
        cJSON_Delete(root);
        return 1;
    }
    printf("解密后的 JSON 数据：\n%s\n", cJSON_PrintPretty(decrypted_root));
    
    // 5. 释放资源
    free(cipher_str);
    cJSON_Delete(root);
    cJSON_Delete(decrypted_root);
    return 0;
}