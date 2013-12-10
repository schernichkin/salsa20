-- | Salsa20 Haskell implementation 
-- Specification: http://cr.yp.to/snuffle/spec.pdf

module Crypto.Cipher.Salsa20 where

import Data.Bits
import Data.Word

data Quarter = Quarter {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       deriving ( Show, Eq )

{-# INLINE quarterround #-}
quarterround :: Quarter -> Quarter
quarterround (Quarter x0 x1 x2 x3) = Quarter y0 y1 y2 y3
    where
        y1 = x1 `xor` ((x0 + x3) `rotateL`  7)
        y2 = x2 `xor` ((y1 + x0) `rotateL`  9)
        y3 = x3 `xor` ((y2 + y1) `rotateL` 13)
        y0 = x0 `xor` ((y3 + y2) `rotateL` 18)

{-# INLINE rotateLeft #-}
rotateLeft :: Quarter -> Quarter
rotateLeft (Quarter x0 x1 x2 x3) = (Quarter x1 x2 x3 x0)

{-# INLINE rotateRight #-}
rotateRight :: Quarter -> Quarter
rotateRight (Quarter x0 x1 x2 x3) = (Quarter x3 x0 x1 x2)

{-# INLINE rotated #-}
rotated :: (Quarter -> Quarter) -> Quarter -> Quarter
rotated f = rotateRight . f . rotateLeft

data State = State {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   deriving ( Show, Eq )

{-# INLINE rowround #-}
rowround :: State -> State
rowround (State x0 x1 x2 x3) = State y0 y1 y2 y3
    where
        y0 =                               quarterround x0
        y1 =  rotated                      quarterround x1
        y2 = (rotated . rotated)           quarterround x2
        y3 = (rotated . rotated . rotated) quarterround x3

{-# INLINE transpose #-}
transpose :: State -> State
transpose (State (Quarter  x0  x1  x2  x3)
                 (Quarter  x4  x5  x6  x7)
                 (Quarter  x8  x9 x10 x11)
                 (Quarter x12 x13 x14 x15)) =
           State (Quarter  x0  x4  x8 x12)
                 (Quarter  x1  x5  x9 x13)
                 (Quarter  x2  x6 x10 x14)
                 (Quarter  x3  x7 x11 x15)

{-# INLINE transposed #-}
transposed :: (State -> State) -> State -> State
transposed f = transpose . f . transpose

{-# INLINE columnround #-}
columnround :: State -> State
columnround = transposed rowround

{-# INLINE doubleround #-}
doubleround :: State -> State
doubleround = rowround . columnround

-- | Manually unrolled doubleround function
{-# INLINE doubleround' #-}
doubleround' (State (Quarter  x0  x1  x2  x3)
                    (Quarter  x4  x5  x6  x7)
                    (Quarter  x8  x9 x10 x11)
                    (Quarter x12 x13 x14 x15)) =
              State (Quarter  z0  z1  z2  z3)
                    (Quarter  z4  z5  z6  z7)
                    (Quarter  z8  z9 z10 z11)
                    (Quarter z12 z13 z14 z15)
    where y4  =  x4  `xor` (( x0 + x12) `rotateL`  7)
          y9  =  x9  `xor` (( x5 +  x1) `rotateL`  7)
          y14 =  x14 `xor` ((x10 +  x6) `rotateL`  7)
          y3  =  x3  `xor` ((x15 + x11) `rotateL`  7)
          y8  =  x8  `xor` (( y4 +  x0) `rotateL`  9)
          y13 =  x13 `xor` (( y9 +  x5) `rotateL`  9)
          y2  =  x2  `xor` ((y14 + x10) `rotateL`  9)
          y7  =  x7  `xor` (( y3 + x15) `rotateL`  9)
          y12 =  x12 `xor` (( y8 +  y4) `rotateL` 13)
          y1  =  x1  `xor` ((y13 +  y9) `rotateL` 13)
          y6  =  x6  `xor` (( y2 + y14) `rotateL` 13)
          y11 =  x11 `xor` (( y7 +  y3) `rotateL` 13)
          y0  =  x0  `xor` ((y12 +  y8) `rotateL` 18)
          y5  =  x5  `xor` (( y1 + y13) `rotateL` 18)
          y10 =  x10 `xor` (( y6 +  y2) `rotateL` 18)
          y15 =  x15 `xor` ((y11 +  y7) `rotateL` 18)

          z1  =  y1  `xor` (( y0 +  y3) `rotateL`  7)
          z6  =  y6  `xor` (( y5 +  y4) `rotateL`  7)
          z11 =  y11 `xor` ((y10 +  y9) `rotateL`  7)
          z12 =  y12 `xor` ((y15 + y14) `rotateL`  7)
          z2  =  y2  `xor` (( z1 +  y0) `rotateL`  9)
          z7  =  y7  `xor` (( z6 +  y5) `rotateL`  9)
          z8  =  y8  `xor` ((z11 + y10) `rotateL`  9)
          z13 =  y13 `xor` ((z12 + y15) `rotateL`  9)
          z3  =  y3  `xor` (( z2 +  z1) `rotateL` 13)
          z4  =  y4  `xor` (( z7 +  z6) `rotateL` 13)
          z9  =  y9  `xor` (( z8 + z11) `rotateL` 13)
          z14 =  y14 `xor` ((z13 + z12) `rotateL` 13)
          z0  =  y0  `xor` (( z3 +  z2) `rotateL` 18)
          z5  =  y5  `xor` (( z4 +  z7) `rotateL` 18)
          z10 =  y10 `xor` (( z9 +  z8) `rotateL` 18)
          z15 =  y15 `xor` ((z14 + z13) `rotateL` 18)

newtype RoundCount = RoundCount Int

rounds20 = RoundCount 10

salsa :: RoundCount -> State -> State
salsa (RoundCount 0) = id
salsa (RoundCount c) = salsa (RoundCount $ c - 1) . doubleround

salsa20 :: State -> State
salsa20 = salsa rounds20

salsa' :: RoundCount -> State -> State
salsa' (RoundCount 0) = id
salsa' (RoundCount c) = salsa' (RoundCount $ c - 1) . doubleround'

salsa20' :: State -> State
salsa20' = salsa' rounds20