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
    sizeOf _ = sizeOf (undefined :: Word32) * 4

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Word32)

    {-# INLINE peek #-}
    peek ptr =
        liftM4 Quarter (peekElemOff ptr' 0)
                       (peekElemOff ptr' 1)
                       (peekElemOff ptr' 2)
                       (peekElemOff ptr' 3)
        where
            ptr' = castPtr ptr

    {-# INLINE poke #-}
    poke ptr (Quarter x0 x1 x2 x3) = do
        pokeElemOff ptr' 0 x0
        pokeElemOff ptr' 1 x1
        pokeElemOff ptr' 2 x2
        pokeElemOff ptr' 3 x3
        where
            ptr' = castPtr ptr

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
    sizeOf _ = sizeOf (undefined :: Quarter) * 4

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr =
        liftM4 Block (peekElemOff ptr' 0)
                     (peekElemOff ptr' 1)
                     (peekElemOff ptr' 2)
                     (peekElemOff ptr' 3)
        where
            ptr' = castPtr ptr

    {-# INLINE poke #-}
    poke ptr (Block x0 x1 x2 x3) = do 
        pokeElemOff ptr' 0 x0
        pokeElemOff ptr' 1 x1
        pokeElemOff ptr' 2 x2
        pokeElemOff ptr' 3 x3
        where
            ptr' = castPtr ptr

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

type Core = Block -> Block

{-# INLINE salsa #-}
salsa :: Int -> Core
salsa rounds initState | (even rounds) && (rounds > 0) = go rounds initState
                       | otherwise = error "Round count shoul be positive even number."
    where
        go 0 = statePlus initState
        go c = go (c - 2) . doubleround

class Key a where
    expand :: Core -> a -> Quarter -> Block

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

instance Key Key128 where
    {-# INLINE expand #-}
    expand core (Key128 k0) = expandSigma core (Quarter 0x61707865 0x3120646e 0x79622d36 0x6b206574) k0 k0

instance Storable Key128 where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOf (undefined :: Quarter)

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr = liftM Key128 (peek $ castPtr ptr)

    {-# INLINE poke #-}
    poke ptr (Key128 k0) = poke (castPtr ptr) k0

data Key256 = Key256 {-# UNPACK #-} !Quarter
                     {-# UNPACK #-} !Quarter
              deriving ( Show, Eq )

instance Key Key256 where
    {-# INLINE expand #-}
    expand core (Key256 k0 k1) = expandSigma core (Quarter 0x61707865 0x3320646e 0x79622d32 0x6b206574) k0 k1

instance Storable Key256 where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOf (undefined :: Quarter) * 2

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Quarter)

    {-# INLINE peek #-}
    peek ptr =
        liftM2 Key256 (peekElemOff ptr' 0)
                      (peekElemOff ptr' 1)
        where
            ptr' = castPtr ptr

    {-# INLINE poke #-}
    poke ptr (Key256 k0 k1) = do
        pokeElemOff ptr' 0 k0
        pokeElemOff ptr' 1 k1
        where
            ptr' = castPtr ptr

data Nounce = Nounce {-# UNPACK #-} !Word32
                     {-# UNPACK #-} !Word32
              deriving ( Show, Eq )

instance Storable Nounce where
    {-# INLINE sizeOf #-}
    sizeOf _ = sizeOf (undefined :: Word32) * 2

    {-# INLINE alignment #-}
    alignment _ = alignment (undefined :: Word32)

    {-# INLINE peek #-}
    peek ptr =
        liftM2 Nounce (peekElemOff ptr' 0)
                      (peekElemOff ptr' 1)
        where
            ptr' = castPtr ptr

    {-# INLINE poke #-}
    poke ptr (Nounce x0 x1) = do
        pokeElemOff ptr' 0 x0
        pokeElemOff ptr' 1 x1
        where
            ptr' = castPtr ptr

data Keystream = Keystream {-# UNPACK #-} !Block
                                           Keystream
                 deriving ( Show, Eq )

keystream :: (Key key) => Core -> key -> Nounce -> Word64 -> Keystream
keystream core key (Nounce n0 n1) = go
    where go i = Keystream (expand' i) $ go (i + 1)
          expand' i = expand core key $ Quarter n0 n1 (fromIntegral i) (fromIntegral $ i `unsafeShiftR` 32)

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