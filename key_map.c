#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <key_map.h>
#include <log.h>
#include <helpers.h>

// Função para inicializar a estrutura key_map
void key_map_init(struct key_map *map) {
    // Verifica se o mapa já foi inicializado
    if (map->key != NULL || map->values != NULL) {
        // flog(LOG_ERR, "Erro: key_map já foi inicializado!\n");
        flog(LOG_INFO, "key_map já foi inicializado!");
        return;
    }

    map->size = 0;
    map->capacity = 4; // Capacidade inicial (pode ser ajustada)
    map->key = malloc(map->capacity * sizeof(char *));
    map->values = malloc(map->capacity * sizeof(uint8_t *));
    if (!map->key || !map->values) {
        flog(LOG_ERR, "Erro ao alocar memória para key_map\n");
        exit(EXIT_FAILURE);
    }
}

// Função para redimensionar a estrutura key_map (se necessário)
void key_map_resize(struct key_map *map) {
    map->capacity *= 2; // Dobra a capacidade atual
    map->key = realloc(map->key, map->capacity * sizeof(char *));
    map->values = realloc(map->values, map->capacity * sizeof(uint8_t *));
    if (!map->key || !map->values) {
        flog(LOG_ERR, "Erro ao redimensionar key_map\n");
        exit(EXIT_FAILURE);
    }
}

// Função para inserir um par chave-valor na estrutura
int key_map_insert(struct key_map *map, const char *key, const uint8_t *value, size_t value_len) {
    if (value_len != KEY_SIZE) {
        flog(LOG_ERR, "Erro: Tamanho do valor inválido! Esperado %d bytes.\n", KEY_SIZE);
        return -1;
    }

    // Redimensiona se a capacidade for atingida
    if (map->size >= map->capacity) {
        key_map_resize(map);
    }

    // Aloca memória para a nova chave e copia os dados
    map->key[map->size] = malloc(INET6_ADDRSTRLEN);
    if (!map->key[map->size]) {
        flog(LOG_ERR, "Erro ao alocar memória para a chave\n");
        return -1;
    }
    strncpy(map->key[map->size], key, INET6_ADDRSTRLEN - 1);
    map->key[map->size][INET6_ADDRSTRLEN - 1] = '\0'; // Garante terminação nula

    // Aloca memória para o valor e copia os dados
    map->values[map->size] = mzalloc(KEY_SIZE);
    if (!map->values[map->size]) {
        flog(LOG_ERR, "Erro ao alocar memória para o valor\n");
        free(map->key[map->size]); // Libera a chave se falhar
        return -1;
    }
    memcpy(map->values[map->size], value, KEY_SIZE);
    flog(LOG_INFO, "Value para ser inserido na key_map: %s", get_hex_str(value, KEY_SIZE));
    flog(LOG_INFO, "Inserido com sucesso na key_map: %s", get_hex_str(map->values[map->size], KEY_SIZE));

    map->size++;
    return 0;
}

// Função para buscar um valor com base na chave
uint8_t *key_map_get(struct key_map *map, const char *key) {
    for (int i = 0; i < map->size; i++) {
        if (strncmp(map->key[i], key, INET6_ADDRSTRLEN) == 0) {
            return map->values[i];
        }
    }
    return NULL; // Retorna NULL se a chave não for encontrada
}

// Função para imprimir o conteúdo da key_map
void key_map_print(struct key_map *map) {
    if (map->size == 0) {
        flog(LOG_INFO, "key_map está vazio.");
        return;
    }

    // Estimativa inicial de tamanho para o buffer
    size_t buffer_size = 1024;
    char *buffer = malloc(buffer_size);
    if (!buffer) {
        flog(LOG_ERR, "Erro ao alocar memória para o buffer de impressão do key_map.");
        return;
    }

    // Começa a construir a string
    size_t offset = snprintf(buffer, buffer_size, "key_map contém %d entradas:\n", map->size);

    for (int i = 0; i < map->size; i++) {
        // Adiciona a chave
        offset += snprintf(buffer + offset, buffer_size - offset, "Chave [%d]: %s\n", i, map->key[i]);

        // Adiciona o valor em hexadecimal
        offset += snprintf(buffer + offset, buffer_size - offset, "Valor [%d]: ", i);

        for (int j = 0; j < KEY_SIZE; j++) {
            // Garante espaço suficiente no buffer
            if (offset + 3 >= buffer_size) { // 2 para %02X e 1 para '\0'
                buffer_size *= 2;
                buffer = realloc(buffer, buffer_size);
                if (!buffer) {
                    flog(LOG_ERR, "Erro ao realocar memória para o buffer de impressão do key_map.");
                    return;
                }
            }

            offset += snprintf(buffer + offset, buffer_size - offset, "%02X", map->values[i][j]);
        }

        // Finaliza a linha
        offset += snprintf(buffer + offset, buffer_size - offset, "\n");
    }

    // Imprime a string completa
    flog(LOG_INFO, "%s", buffer);

    // Libera o buffer
    free(buffer);
}


// Função para liberar a memória alocada pela key_map
void key_map_free(struct key_map *map) {
    for (int i = 0; i < map->size; i++) {
        free(map->key[i]);
        free(map->values[i]);
    }
    free(map->key);
    free(map->values);
}