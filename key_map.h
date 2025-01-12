#ifndef __RPLD_KEY_MAP__
#define __RPLD_KEY_MAP__

#include <stdlib.h>
#include <stdint.h>

#define KEY_SIZE 32

struct key_map {
    int size;        // Número de entradas atuais
    int capacity;    // Capacidade máxima atual
    char **key;      // Ponteiro para um array dinâmico de strings
    u_int8_t **values; // Ponteiro para um array dinâmico de arrays de bytes
};

void key_map_init(struct key_map *map);
void key_map_resize(struct key_map *map);
int key_map_insert(struct key_map *map, const char *key, const uint8_t *value, size_t value_len);
uint8_t *key_map_get(struct key_map *map, const char *key);
void key_map_print(struct key_map *map);
void key_map_free(struct key_map *map);
#endif