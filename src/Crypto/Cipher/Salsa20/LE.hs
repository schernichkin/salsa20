module Crypto.Cipher.Salsa20.LE where

import           Control.Monad
import           Data.Bits
import           Data.ByteString.Internal
import           Data.Word
import           Foreign.ForeignPtr
import           Foreign.Ptr
import           Foreign.Storable

data Quarter = Quarter {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       {-# UNPACK #-} !Word32
                       deriving ( Show, Eq )

instance Storable Quarter where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOfWord32 * 4

    {-# INLINE alignment #-}
    alignment _ = alignment (0 :: Word32)

    {-# INLINE peek #-}
    peek ptr = liftM4 Quarter (peek $ castPtr ptr)
                              (peek $ ptr `plusPtr` sizeOfWord32)
                              (peek $ ptr `plusPtr` (sizeOfWord32 * 2))
                              (peek $ ptr `plusPtr` (sizeOfWord32 * 3))

    {-# INLINE poke #-}
    poke ptr (Quarter x0 x1 x2 x3) = do poke (castPtr ptr) x0
                                        poke (ptr `plusPtr` sizeOfWord32) x1
                                        poke (ptr `plusPtr` (sizeOfWord32 * 2)) x2
                                        poke (ptr `plusPtr` (sizeOfWord32 * 3)) x3

{-# INLINE sizeOfWord32 #-}
sizeOfWord32 :: Int
sizeOfWord32 = sizeOf (0 :: Word32)

{-# INLINE sizeOfQuarter #-}
sizeOfQuarter :: Int
sizeOfQuarter = sizeOf (undefined :: Quarter)

{-# INLINE quarterPlus #-}
quarterPlus :: Quarter -> Quarter -> Quarter
quarterPlus (Quarter x0 x1 x2 x3) (Quarter y0 y1 y2 y3) = Quarter (x0 + y0) (x1 + y1) (x2 + y2) (x3 + y3)

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

data Block = Block {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   {-# UNPACK #-} !Quarter
                   deriving ( Show, Eq )

instance Storable Block where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOfQuarter * 4

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr = liftM4 Block (peek $ castPtr ptr)
                            (peek $ ptr `plusPtr` sizeOfQuarter)
                            (peek $ ptr `plusPtr` (sizeOfQuarter * 2))
                            (peek $ ptr `plusPtr` (sizeOfQuarter * 3))

    {-# INLINE poke #-}
    poke ptr (Block x0 x1 x2 x3) = do poke (castPtr ptr) x0
                                      poke (ptr `plusPtr` sizeOfQuarter) x1
                                      poke (ptr `plusPtr` (sizeOfQuarter * 2)) x2
                                      poke (ptr `plusPtr` (sizeOfQuarter * 3)) x3

{-# SPECIALIZE INLINE readBinary :: ByteString -> Maybe (Quarter, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> Maybe (Block, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> Maybe (Key128, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> Maybe (Key256, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> Maybe (Nounce, ByteString) #-}
readBinary :: (Storable a) => ByteString -> Maybe (a, ByteString)
readBinary bs | l < size = Nothing
              | otherwise = Just (value, fromForeignPtr p (s + size) (l - size))
    where (p, s, l) = toForeignPtr bs
          value = inlinePerformIO $ withForeignPtr p $ peek . castPtr
          size = sizeOf value

{-# SPECIALIZE INLINE writeBinary :: Quarter -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Block -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Key128 -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Key256 -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Nounce -> ByteString #-}
writeBinary :: (Storable a) => a -> ByteString
writeBinary s = unsafeCreate (sizeOf s) $ \p -> poke (castPtr p) s

{-# INLINE statePlus #-}
statePlus :: Block -> Block -> Block
statePlus (Block x0 x1 x2 x3) (Block y0 y1 y2 y3) = Block (x0 `quarterPlus` y0) (x1 `quarterPlus` y1) (x2 `quarterPlus` y2) (x3 `quarterPlus` y3)

{-# INLINE rowround #-}
rowround :: Block -> Block
rowround (Block x0 x1 x2 x3) = Block y0 y1 y2 y3
    where
        y0 =                               quarterround x0
        y1 =  rotated                      quarterround x1
        y2 = (rotated . rotated)           quarterround x2
        y3 = (rotated . rotated . rotated) quarterround x3

{-# INLINE transpose #-}
transpose :: Block -> Block
transpose (Block (Quarter  x0  x1  x2  x3)
                 (Quarter  x4  x5  x6  x7)
                 (Quarter  x8  x9 x10 x11)
                 (Quarter x12 x13 x14 x15)) =
           Block (Quarter  x0  x4  x8 x12)
                 (Quarter  x1  x5  x9 x13)
                 (Quarter  x2  x6 x10 x14)
                 (Quarter  x3  x7 x11 x15)

{-# INLINE transposed #-}
transposed :: (Block -> Block) -> Block -> Block
transposed f = transpose . f . transpose

{-# INLINE columnround #-}
columnround :: Block -> Block
columnround = transposed rowround

{-# INLINE doubleround #-}
doubleround :: Block -> Block
doubleround = rowround . columnround

-- | Manually unrolled doubleround function
-- Vanilla code runs faster for some reason
-- I've left manually expanded code for profiling
{-# INLINE doubleround' #-}
doubleround' (Block (Quarter  x0  x1  x2  x3)
                    (Quarter  x4  x5  x6  x7)
                    (Quarter  x8  x9 x10 x11)
                    (Quarter x12 x13 x14 x15)) =
              Block (Quarter  z0  z1  z2  z3)
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

newtype RoundCount = RoundCount Int -- TO DO: do not export

{-# INLINE rounds8 #-}
rounds8 :: RoundCount
rounds8 = RoundCount 4

{-# INLINE rounds12 #-}
rounds12 :: RoundCount
rounds12 = RoundCount 6

{-# INLINE rounds20 #-}
rounds20 :: RoundCount
rounds20 = RoundCount 10

type Core = Block -> Block

{-# INLINE salsa #-}
salsa :: Int -> Core
salsa rounds initState | (even rounds) && (rounds > 0) = go rounds initState
                       | otherwise = error "Round count shoul be positive even number."
    where
        go 0 = statePlus initState
        go c = go (c - 2) . doubleround

{-# INLINE salsa20 #-}
salsa20 :: Core
salsa20 = salsa 20

{-# INLINE salsa' #-}
salsa' :: RoundCount -> Core
salsa' count initState = go count initState
    where go (RoundCount 0) = statePlus initState
          go (RoundCount c) = go (RoundCount $ c - 1) . doubleround'

{-# INLINE salsa20' #-}
salsa20' :: Core
salsa20' = salsa' rounds20

{-# INLINE expandSigma #-}
expandSigma :: Core -> Quarter -> Quarter -> Quarter -> Quarter -> Block
expandSigma salsaCore
            (Quarter  s0  s1  s2  s3)
            (Quarter k00 k01 k02 k03)
            (Quarter k10 k11 k12 k13)
            (Quarter  n0  n1  n2  n3) =
            salsaCore $ Block
            (Quarter  s0 k00 k01 k02)
            (Quarter k03  s1  n0  n1)
            (Quarter  n2  n3  s2 k10)
            (Quarter k11 k12 k13  s3)

newtype Key128 = Key128 Quarter deriving ( Show, Eq )

instance Storable Key128 where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOfQuarter

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr = liftM Key128 (peek $ castPtr ptr)

    {-# INLINE poke #-}
    poke ptr (Key128 k0) = poke (castPtr ptr) k0

type Expand key = key -> Quarter -> Block
    
{-# INLINE expand128 #-}
expand128 :: Core -> Expand Key128
expand128 core (Key128 k0) = expandSigma core (Quarter 0x61707865 0x3120646e 0x79622d36 0x6b206574) k0 k0

data Key256 = Key256 {-# UNPACK #-} !Quarter
                     {-# UNPACK #-} !Quarter
              deriving ( Show, Eq )

instance Storable Key256 where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOfQuarter * 2

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr = liftM2 Key256 (peek $ castPtr ptr)
                             (peek $ ptr `plusPtr` sizeOfQuarter)

    {-# INLINE poke #-}
    poke ptr (Key256 k0 k1) = do poke (castPtr ptr) k0
                                 poke (ptr `plusPtr` sizeOfQuarter) k1

{-# INLINE expand256 #-}
expand256 :: Core -> Expand Key256
expand256 core (Key256 k0 k1) = expandSigma core (Quarter 0x61707865 0x3320646e 0x79622d32 0x6b206574) k0 k1

data Nounce = Nounce {-# UNPACK #-} !Word32
                     {-# UNPACK #-} !Word32
              deriving ( Show, Eq )

instance Storable Nounce where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOfWord32 * 2

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Word32)

    {-# INLINE peek #-}
    peek ptr = liftM2 Nounce (peek $ castPtr ptr)
                             (peek $ ptr `plusPtr` sizeOfWord32)

    {-# INLINE poke #-}
    poke ptr (Nounce x0 x1) = do poke (castPtr ptr) x0
                                 poke (ptr `plusPtr` sizeOfWord32) x1

newtype SeqNum = SeqNum Word64 deriving ( Show, Eq )

data Keystream = Keystream {-# UNPACK #-} !Block
                                           Keystream
                 deriving ( Show, Eq )

keystream :: Expand key -> key -> Nounce -> SeqNum -> Keystream
keystream expand key (Nounce n0 n1) = go
    where go seqNum@(SeqNum i) = Keystream (expand' seqNum) $ go (SeqNum $ i + 1)
          expand' (SeqNum i) = expand key $ Quarter n0 n1 (fromIntegral i) (fromIntegral $ i `shiftR` 32)

newtype CryptProcess = CryptProcess (ByteString -> (ByteString, CryptProcess))

createCryptProcess :: (Block -> Block) -> ((Block -> Block) -> Key128 -> Quarter -> Block) -> Key128 -> Nounce -> CryptProcess
createCryptProcess salsaCore = undefined
    where
{-
crypt (Cont f) = f
crypt (New key (Nounce n0 n1)) = undefined
    where keyState :: Word64 -> Block
          keyState seqNum = expand' $ Quarter n0 n1 undefined undefined
          expand' = case key of
                        Key16 k0    -> expand16 k0
                        Key32 k0 k1 -> expand32 k0 k1   
-}