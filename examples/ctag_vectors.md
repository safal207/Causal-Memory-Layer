# CTAG Test Vectors (v0.4)

All vectors use the canonical v0.4 hash:

`H(parent)` = FNV-1a 64-bit of the lowercase UUID string (with hyphens).

CTAG layout:

```
CTAG = (DOM<<12) | (CLASS<<8) | (GEN<<4) | (LHINT<<1) | SEAL
```

## Vector 1

- DOM = USER (4)
- CLASS = EXEC (3)
- GEN = 2
- SEAL = 0
- parent = `550e8400-e29b-41d4-a716-446655440000`

Computed:
- H(parent) = `0xfbb0538ee83a5048`
- LHINT = 3
- CTAG = `0x4326`

## Vector 2

- DOM = KERNEL (1)
- CLASS = CONFIG (8)
- GEN = 7
- SEAL = 1
- parent = `123e4567-e89b-12d3-a456-426614174000`

Computed:
- H(parent) = `0x8da4bf2f8d2be9bf`
- LHINT = 3
- CTAG = `0x1877`

## Vector 3

- DOM = THIRD_PARTY (12)
- CLASS = OVERRIDE (14)
- GEN = 15
- SEAL = 0
- parent = `00000000-0000-0000-0000-000000000001`

Computed:
- H(parent) = `0x7c384b6218f2983e`
- LHINT = 4
- CTAG = `0xCEF8`
