module Crypto.Cipher.Salsa20.LE where

import           Control.Exception ( assert )
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

{-# INLINE quarterRound #-}
quarterRound :: Quarter -> Quarter
quarterRound (Quarter x0 x1 x2 x3) = Quarter y0 y1 y2 y3
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

readBlock :: ByteString -> Maybe (Block, ByteString)
readBlock = readBinary

writeBlock :: Block -> ByteString
writeBlock = writeBinary

{-# INLINE plusBlock #-}
plusBlock :: Block -> Block -> Block
plusBlock (Block x0 x1 x2 x3) (Block y0 y1 y2 y3) = Block (x0 `plusQuarter` y0) (x1 `plusQuarter` y1) (x2 `plusQuarter` y2) (x3 `plusQuarter` y3)

{-# INLINE xorBlock #-}
xorBlock :: Block -> Block -> Block
xorBlock (Block x0 x1 x2 x3) (Block y0 y1 y2 y3) = Block (x0 `xorQuarter` y0) (x1 `xorQuarter` y1) (x2 `xorQuarter` y2) (x3 `xorQuarter` y3)

{-# INLINE rowRound #-}
rowRound :: Block -> Block
rowRound (Block x0 x1 x2 x3) = Block y0 y1 y2 y3
    where
        y0 =                               quarterRound x0
        y1 =  rotated                      quarterRound x1
        y2 = (rotated . rotated)           quarterRound x2
        y3 = (rotated . rotated . rotated) quarterRound x3

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

{-# INLINE columnRound #-}
columnRound :: Block -> Block
columnRound = transposed rowRound

{-# INLINE doubleRound #-}
doubleRound :: Block -> Block
doubleRound = rowRound . columnRound

type Core = Block -> Block

{-# INLINE salsa #-}
salsa :: Int -> Core
salsa rounds initBlock = assert ((even rounds) && (rounds > 0)) $ go (rounds `unsafeShiftR` 1) initBlock
    where
        go 0 block = block `plusBlock` initBlock
        go n block = go (n - 1) $! doubleRound block

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

readKey128 :: ByteString -> Maybe (Key128, ByteString)
readKey128 = readBinary

writeKey128 :: Key128 -> ByteString
writeKey128 = writeBinary

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

readKey256 :: ByteString -> Maybe (Key256, ByteString)
readKey256 = readBinary

writeKey256 :: Key256 -> ByteString
writeKey256 = writeBinary

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

readNounce :: ByteString -> Maybe (Nounce, ByteString)
readNounce = readBinary

writeNounce :: Nounce -> ByteString
writeNounce = writeBinary

data Keystream = Keystream {-# UNPACK #-} !Block
                                           Keystream
                 deriving ( Show, Eq )

{-# SPECIALISE INLINE keystream :: Core -> Key128 -> Nounce -> Word64 -> Keystream #-}
{-# SPECIALISE INLINE keystream :: Core -> Key256 -> Nounce -> Word64 -> Keystream #-}
keystream :: (Key key) => Core -> key -> Nounce -> Word64 -> Keystream
keystream core key (Nounce n0 n1) = go
    where
        go i = Keystream (expand' i) $ go (i + 1)
        expand' i = expand core key $ Quarter n0 n1 (fromIntegral i) (fromIntegral $ i `unsafeShiftR` 32)

newtype CryptProcess = CryptProcess { runCryptProcess :: ByteString -> (ByteString, CryptProcess) }

crypt :: (Key key) => Core -> key -> Nounce -> Word64 -> CryptProcess
crypt core key nounce seqNum = CryptProcess $ startCrypt $ keystream core key nounce seqNum

{-# INLINE blockSize #-}
blockSize :: Int
blockSize = sizeOf (undefined :: Block)

{-# INLINE startCrypt #-}
startCrypt :: Keystream -> ByteString -> (ByteString, CryptProcess)
startCrypt keyStream srcStream
    | srcLength >= blockSize = cryptBytestring $ \dstPtr srcPtr -> do
        alignedSrcPtr <- copySourceIfUnaligned dstPtr srcPtr srcLength
        (dstPtr', srcPtr', keyStream') <- cryptBlocks keyStream blockCount dstPtr alignedSrcPtr
        if bytesRemains == 0
            then return $ CryptProcess $ startCrypt keyStream'
            else cryptSubBlock keyStream' bytesRemains (castPtr dstPtr') (castPtr srcPtr')
    | srcLength == 0 = (srcStream, CryptProcess $ startCrypt keyStream)
    | otherwise = assert (srcLength < blockSize) $ cryptBytestring $ cryptSubBlock keyStream srcLength
    where
        (srcFp, srcOffset, srcLength) = toForeignPtr srcStream
        (blockCount, bytesRemains) = srcLength `quotRem` blockSize

        {-# INLINE cryptBytestring #-}
        cryptBytestring :: (Ptr a -> Ptr Word8 -> IO CryptProcess) -> (ByteString, CryptProcess)
        cryptBytestring f = unsafeDupablePerformIO $ do
            dstFp <- mallocForeignPtrBytes srcLength
            process <- withForeignPtr dstFp $ \dstPtr ->
                       withForeignPtr srcFp $ \srcBasePtr ->
                       f dstPtr (srcBasePtr `plusPtr` srcOffset)
            return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)

{-# INLINE continueCrypt #-}
continueCrypt :: ForeignPtr Block -> Int -> Keystream-> ByteString -> (ByteString, CryptProcess)
continueCrypt keyFp keyUsed keyStream srcStream -- TODO add key used assert
    | srcLength >= blockSize = unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes (srcLength + blockSize)
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr, srcPtr) <- bytesXor (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyUsed) keyRemains
            alignedSrcPtr <- copySourceIfUnaligned (castPtr dstPtr) srcPtr (srcLength - keyRemains)
            (dstPtr', srcPtr', keyStream') <- cryptBlocks keyStream blockCount (castPtr dstPtr) alignedSrcPtr
            if bytesRemains == 0
               then return $ CryptProcess $ startCrypt keyStream'
               else  cryptSubBlock keyStream' bytesRemains (castPtr dstPtr') (castPtr srcPtr')
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    | srcLength  == 0 = (srcStream, CryptProcess $ continueCrypt keyFp keyUsed keyStream)
    | otherwise = assert (srcLength < blockSize) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes srcLength
        process <- withForeignPtr dstFp $ \dstPtr ->
                   withForeignPtr srcFp $ \srcBasePtr -> do
            continueCryptSubBlock keyFp keyUsed keyStream srcLength dstPtr (srcBasePtr `plusPtr` srcOffset)
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    where
        (srcFp, srcOffset, srcLength) = toForeignPtr srcStream
        keyRemains = (blockSize - keyUsed)
        (blockCount, bytesRemains) = (srcLength - keyRemains) `quotRem` blockSize

{-# INLINE copySourceIfUnaligned #-}
copySourceIfUnaligned :: Ptr Block -> Ptr Word8 -> Int -> IO (Ptr Block)
copySourceIfUnaligned dstPtr srcPtr size
    | srcPtr `alignPtr` alignment (undefined :: Block) == srcPtr = return $ castPtr srcPtr
    | otherwise = do
        copyBytes (castPtr dstPtr) srcPtr size
        return dstPtr

{-# INLINE cryptBlocks #-}
cryptBlocks :: Keystream -> Int -> Ptr Block -> Ptr Block -> IO (Ptr Block, Ptr Block, Keystream)
cryptBlocks keyStream@(Keystream key nextKey) blocks dstPtr srcPtr
    | blocks == 0 = return $ (dstPtr, srcPtr, keyStream)
    | otherwise = assert (blocks > 0) $ do
        block <- peek srcPtr
        poke dstPtr $ block `xorBlock` key
        cryptBlocks nextKey (blocks - 1) (dstPtr `plusPtr` blockSize) (srcPtr `plusPtr` blockSize)

-- | Encrypt chunk smaller than block size
{-# INLINE cryptSubBlock #-}
cryptSubBlock :: Keystream -> Int -> Ptr Word8 -> Ptr Word8 -> IO CryptProcess
cryptSubBlock (Keystream currentKey nextKey) size dstPtr srcPtr = assert (size > 0 && size < blockSize) $ do
    keyRemainsFp <- mallocForeignPtr
    withForeignPtr keyRemainsFp $ \keyRemainsPtr -> do
        poke keyRemainsPtr currentKey
        void $ bytesXor dstPtr srcPtr (castPtr keyRemainsPtr) size
    return $ CryptProcess $ continueCrypt keyRemainsFp size nextKey

-- | Encrypt chunk smaller than block size with previous key's remains.
-- Chunk can be either larger or smaller than key remains, but should be always smaller than block size.
{-# INLINE continueCryptSubBlock #-}
continueCryptSubBlock :: ForeignPtr Block -> Int -> Keystream -> Int -> Ptr Word8 -> Ptr Word8 -> IO CryptProcess
continueCryptSubBlock keyFp keyUsed keyStream size dstPtr srcPtr = assert (size > 0 && size < blockSize) $
    case blockSize - keyUsed of
        keyRemains
            | size < keyRemains -> do
                withForeignPtr keyFp $ \keyBasePtr -> void $ bytesXor dstPtr srcPtr (keyBasePtr `plusPtr` keyUsed) size
                return $ CryptProcess $ continueCrypt keyFp (keyUsed + size) keyStream
            | size > keyRemains ->  do
                (dstPtr', srcPtr') <- withForeignPtr keyFp $ \keyBasePtr -> bytesXor dstPtr srcPtr (keyBasePtr `plusPtr` keyUsed) keyRemains
                cryptSubBlock keyStream (size - keyRemains) dstPtr' srcPtr'
            | otherwise -> assert (size == keyRemains) $ do
                withForeignPtr keyFp $ \keyBasePtr -> void $ bytesXor dstPtr srcPtr (keyBasePtr `plusPtr` keyUsed) size
                return $ CryptProcess $ startCrypt keyStream

{-# INLINE bytesXor #-}
bytesXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO (Ptr Word8, Ptr Word8)
bytesXor dstPtr srcPtr keyPtr count
    | count == 0 = return (dstPtr, srcPtr)
    | otherwise = assert (count > 0) $ do
        x <- peek srcPtr
        k <- peek keyPtr
        poke dstPtr (x `xor` k)
        bytesXor (dstPtr `plusPtr` 1) (srcPtr `plusPtr` 1) (keyPtr `plusPtr` 1) (count - 1)

{-# SPECIALISE INLINE readBinary :: ByteString -> Maybe (Block, ByteString) #-}
{-# SPECIALISE INLINE readBinary :: ByteString -> Maybe (Key128, ByteString) #-}
{-# SPECIALISE INLINE readBinary :: ByteString -> Maybe (Key256, ByteString) #-}
{-# SPECIALISE INLINE readBinary :: ByteString -> Maybe (Nounce, ByteString) #-}
readBinary :: (Storable a) => ByteString -> Maybe (a, ByteString)
readBinary byteString
    | len >= size = Just (value, fromForeignPtr fp (offset + size) (len - size))
    | otherwise = Nothing
    where
        (fp, offset, len) = toForeignPtr byteString
        size = sizeOf value
        align = alignment value
        value = unsafeDupablePerformIO $ withForeignPtr fp $ \ptr -> alignValue size align (ptr `plusPtr` offset) peek

{-# INLINE alignValue #-}
alignValue :: Int -> Int -> Ptr a -> (Ptr a -> IO b) -> IO b
alignValue size align ptr f
    | aligned = f ptr
    | otherwise = allocaBytesAligned size align $ \buffer -> do
        copyBytes buffer ptr size
        f buffer
    where aligned = ptr `alignPtr` align == ptr

{-# SPECIALISE INLINE writeBinary :: Block -> ByteString #-}
{-# SPECIALISE INLINE writeBinary :: Key128 -> ByteString #-}
{-# SPECIALISE INLINE writeBinary :: Key256 -> ByteString #-}
{-# SPECIALISE INLINE writeBinary :: Nounce -> ByteString #-}
writeBinary :: (Storable a) => a -> ByteString
writeBinary value = unsafeDupablePerformIO $ do
    fp <- mallocForeignPtr
    withForeignPtr fp $ \p -> poke p value
    return $ fromForeignPtr (castForeignPtr fp) 0 (sizeOf value)