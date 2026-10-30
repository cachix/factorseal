#ifndef FACTORSEAL_H
#define FACTORSEAL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t length;
} FactorSealBuffer;

FactorSealBuffer factorseal_call(const uint8_t *request, size_t length);
FactorSealBuffer factorseal_scan(const uint8_t *pixels, size_t length, size_t width, size_t height, size_t stride);
void factorseal_seal(void);
void factorseal_free(FactorSealBuffer buffer);

#endif
