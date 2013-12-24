module Crypto.Cipher.Salsa20.LE where

import           Control.Exception
import           Control.Monad
import           Data.Bits
import           Data.ByteString.Internal hiding (PS)
import           Data.Word
import           Foreign.ForeignPtr
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable
import           System.IO.Unsafe

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

{-# INLINE plusQuarter #-}
plusQuarter :: Quarter -> Quarter -> Quarter
plusQuarter (Quarter x0 x1 x2 x3) (Quarter y0 y1 y2 y3) = Quarter (x0 + y0) (x1 + y1) (x2 + y2) (x3 + y3)

{-# INLINE xorQuarter #-}
xorQuarter :: Quarter -> Quarter -> Quarter
xorQuarter (Quarter x0 x1 x2 x3) (Quarter y0 y1 y2 y3) = Quarter (x0 `xor` y0) (x1 `xor` y1) (x2 `xor` y2) (x3 `xor` y3)

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

{-# INLINE plusState #-}
plusState :: Block -> Block -> Block
plusState (Block x0 x1 x2 x3) (Block y0 y1 y2 y3) = Block (x0 `plusQuarter` y0) (x1 `plusQuarter` y1) (x2 `plusQuarter` y2) (x3 `plusQuarter` y3)

{-# INLINE xorState #-}
xorState :: Block -> Block -> Block
xorState (Block x0 x1 x2 x3) (Block y0 y1 y2 y3) = Block (x0 `xorQuarter` y0) (x1 `xorQuarter` y1) (x2 `xorQuarter` y2) (x3 `xorQuarter` y3)

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
salsa rounds initState = assert ((even rounds) && (rounds > 0)) $ go rounds initState
    where
        go 0 = plusState initState
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

{-# SPECIALIZE INLINE keystream :: Core -> Key128 -> Nounce -> Word64 -> Keystream #-}
{-# SPECIALIZE INLINE keystream :: Core -> Key256 -> Nounce -> Word64 -> Keystream #-}
keystream :: (Key key) => Core -> key -> Nounce -> Word64 -> Keystream
keystream core key (Nounce n0 n1) = go
    where
        go i = Keystream (expand' i) $ go (i + 1)
        expand' i = expand core key $ Quarter n0 n1 (fromIntegral i) (fromIntegral $ i `unsafeShiftR` 32)

newtype CryptProcess = CryptProcess (ByteString -> (ByteString, CryptProcess))

{-# SPECIALIZE INLINE crypt :: Core -> Key128 -> Nounce -> Word64 -> CryptProcess #-}
{-# SPECIALIZE INLINE crypt :: Core -> Key256 -> Nounce -> Word64 -> CryptProcess #-}
crypt :: (Key key) => Core -> key -> Nounce -> Word64 -> CryptProcess
crypt core key nounce seqNum = CryptProcess $ startCrypt $ keystream core key nounce seqNum
    where
        startCrypt :: Keystream -> ByteString -> (ByteString, CryptProcess)
        startCrypt keyStream dataStream
            | dataLength == 0 = (dataStream, CryptProcess $ startCrypt keyStream)
            | otherwise = unsafeDupablePerformIO
                        $ withForeignPtr fp
                        $ \ptr -> alignValue dataLength blockSize (ptr `plusPtr` dataOffset)
                        $ \srcPtr -> do
                            dstFp <- mallocForeignPtrBytes dataLength
                            (dstPtr', srcPtr', keyStream') <- withForeignPtr dstFp
                                $ \dstPtr -> cryptAligned dstPtr srcPtr keyStream blockCount
                            process <- case bytesRemains of
                                           0 -> return $ CryptProcess $ startCrypt keyStream
                                           1 -> error $ "bytesRemains: " ++ (show bytesRemains)
                            return (fromForeignPtr (castForeignPtr dstFp) 0 dataLength, process)
            where
                (fp, dataOffset, dataLength) = toForeignPtr dataStream
                (blockCount, bytesRemains) = dataLength `quotRem` blockSize -- TODO: Check performance on bitwise shiftR and .&.

        cryptAligned :: Ptr Block -> Ptr Block -> Keystream -> Int -> IO (Ptr Block, Ptr Block, Keystream)
        cryptAligned dstPtr srcPtr ks@(Keystream currentKey nextKey) n
            | n == 0 = return $ (dstPtr, srcPtr, ks)
            | otherwise = do
                blockXor dstPtr srcPtr currentKey
                cryptAligned (dstPtr `plusPtr` blockSize) (srcPtr `plusPtr` blockSize) nextKey (n - 1)

        cryptUnaligned = undefined
            
        blockSize = sizeOf (undefined :: Block)

        blockXor :: Ptr Block -> Ptr Block -> Block -> IO ()
        blockXor dstPtr srcPtr keyBlock = poke dstPtr . xorState keyBlock =<< peek srcPtr

        byteXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
        byteXor _ _ _ 0 = return ()
        byteXor dstPtr srcPtr keyPtr n = do
            x <- peek srcPtr
            y <- peek keyPtr
            poke dstPtr (x `xor` y)
            byteXor (dstPtr `plusPtr` 1) (srcPtr `plusPtr` 1) (keyPtr `plusPtr` 1) (n - 1)

{-# INLINE alignValue #-}
alignValue :: Int -> Int -> Ptr a -> (Ptr a -> IO b) -> IO b
alignValue size align ptr f
    | aligned = f ptr
    | otherwise = allocaBytesAligned size align $ \buffer -> do
        copyBytes buffer ptr size
        f buffer
    where aligned = ptr `alignPtr` align == ptr

{-# SPECIALIZE INLINE readBinary :: ByteString -> (Quarter, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> (Block, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> (Key128, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> (Key256, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> (Nounce, ByteString) #-}
{-# SPECIALIZE INLINE readBinary :: ByteString -> (Word64, ByteString) #-}
readBinary :: (Storable a) => ByteString -> (a, ByteString)
readBinary bs = assert (stringLength <= size) $ (value, fromForeignPtr fp (offset + size) (stringLength - size))
    where
        (fp, offset, stringLength) = toForeignPtr bs
        size = sizeOf value
        align = alignment value
        value = unsafeDupablePerformIO
              $ withForeignPtr fp
              $ \p -> alignValue size align (p `plusPtr` offset) peek

{-# SPECIALIZE INLINE writeBinary :: Quarter -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Block -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Key128 -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Key256 -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Nounce -> ByteString #-}
{-# SPECIALIZE INLINE writeBinary :: Word64 -> ByteString #-}
writeBinary :: (Storable a) => a -> ByteString
writeBinary value = unsafeDupablePerformIO $ do
    fp <- mallocForeignPtr
    withForeignPtr fp $ \p -> poke p value
    return $ fromForeignPtr (castForeignPtr fp) 0 (sizeOf value)