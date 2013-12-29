module Crypto.Cipher.Salsa20.LE where

import           Control.Exception ( assert )
import           Control.Monad
import           Control.Applicative
import           Data.Bits
import           Data.ByteString.Internal hiding (PS)
import           Data.Word
import           Foreign.ForeignPtr
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable
import           System.IO.Unsafe
import           Debug.Trace

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

{-# SPECIALISE INLINE keyStream :: Core -> Key128 -> Nounce -> Word64 -> Keystream #-}
{-# SPECIALISE INLINE keyStream :: Core -> Key256 -> Nounce -> Word64 -> Keystream #-}
keyStream :: (Key key) => Core -> key -> Nounce -> Word64 -> Keystream
keyStream core key (Nounce n0 n1) = go
    where
        go i = Keystream (expand' i) $ go (i + 1)
        expand' i = expand core key $ Quarter n0 n1 (fromIntegral i) (fromIntegral $ i `unsafeShiftR` 32)

newtype CryptProcess = CryptProcess { runCryptProcess :: ByteString -> (ByteString, CryptProcess) }

crypt :: (Key key) => Core -> key -> Nounce -> Word64 -> CryptProcess
crypt core key nounce seqNum = CryptProcess $ startCrypt $ keyStream core key nounce seqNum

{-# INLINE startCrypt #-}
startCrypt :: Keystream -> ByteString -> (ByteString, CryptProcess)
startCrypt keyStream src
    -- skip empty block
    | srcLength == 0 = (src, CryptProcess $ startCrypt keyStream)

    -- crypt less then one block and store key remains
    | srcLength < blockSize =
        cryptChunk srcFp srcLength blockSize $ \dstBasePtr srcBasePtr -> cryptRemains dstBasePtr 0 (srcBasePtr `plusPtr` srcOffset) keyStream srcLength

    -- crypt whole number of blocks (more than one, one is handled by special case)
    | remains == 0 =
        cryptChunk srcFp srcLength srcLength $ \dstBasePtr srcBasePtr -> do
            (nextKey, _) <- blockXor dstBasePtr (srcBasePtr `plusPtr` srcOffset) keyStream srcLength
            return $ const $ CryptProcess $ startCrypt nextKey

    -- crypt whole number of blocks + part of the key and store key remains for the next step
    | otherwise =
        cryptChunk srcFp srcLength (srcLength + blockSize - remains) $ \dstBasePtr srcBasePtr -> do
            (Keystream key nextKey, blockBytes) <- blockXor dstBasePtr (srcBasePtr `plusPtr` srcOffset) keyStream srcLength
            let dstPtr = dstBasePtr `plusPtr` blockBytes
            poke dstPtr key
            void $ bytesXor2 dstPtr (srcBasePtr `plusPtr` (srcOffset + blockBytes)) remains
            return $ \dstFp -> CryptProcess $ continueCrypt (fromForeignPtr (castForeignPtr dstFp) srcLength (blockSize - remains)) nextKey
    where
        (srcFp, srcOffset, srcLength) = toForeignPtr src
        remains = assert (blockSize == 64) $ srcLength .&. 0x3F

{-# INLINE continueCrypt #-}
continueCrypt :: ByteString -> Keystream -> ByteString -> (ByteString, CryptProcess)
continueCrypt storedKey keyStream  src
    -- skip empty block
    | srcLength == 0 = (src, CryptProcess $ continueCrypt storedKey keyStream)
    -- use all key remains to encode chunk
    | srcLength == keyLength = unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes srcLength
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            bytesXor3 (castPtr dstBasePtr) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) srcLength
            return $ CryptProcess $ startCrypt keyStream
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    -- use all key remains + some whole key blocks
    | srcLength >= blockSize && remains == 0 = assert (blockCount > 0) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (srcLength + blockSize)
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyLength
            alignedSrcPtr <- copySourceIfUnaligned (castPtr dstPtr') srcPtr' (blockCount * blockSize)  -- (srcLength - keyLength)
            nextKey' <- snd <$> cryptBlocks keyStream blockCount (castPtr dstPtr') alignedSrcPtr
            return $ CryptProcess $ startCrypt nextKey'
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    -- use all key remains + some whole key blocks + part of the key and store key remains for the next step
    | srcLength >= blockSize = assert (remains > 0) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (srcLength + blockSize + blockSize) -- one block for alignment one for new key remains
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyLength
            alignedSrcPtr' <- copySourceIfUnaligned (castPtr dstPtr') srcPtr' (blockCount * blockSize) -- (srcLength - keyLength - remains)
            (dstPtr'', keyStream''@(Keystream key'' nextKey'')) <- cryptBlocks keyStream blockCount (castPtr dstPtr') alignedSrcPtr'
            poke dstPtr'' key''
            void $ bytesXor2 (castPtr dstPtr'') (srcPtr' `plusPtr` (srcLength - remains - keyLength)) remains
            return  $ CryptProcess $ continueCrypt (fromForeignPtr (castForeignPtr dstFp) (keyUsed + srcLength) (blockSize - remains)) nextKey'' 
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    -- use some of key remains to encode the block and store remains in the new block to allow GC reclaim old block
    | srcLength < keyLength = assert (srcLength > 0) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes (srcLength + (keyLength - srcLength))
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', keyPtr') <- bytesXor3 dstBasePtr (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) srcLength
            copyBytes dstPtr' keyPtr' (keyLength - srcLength)
            return $ CryptProcess $ continueCrypt (fromForeignPtr (castForeignPtr dstFp) srcLength (blockSize - keyUsed - srcLength)) keyStream
        return (fromForeignPtr dstFp 0 srcLength, process)
    -- use all key remains to encode the block and part of new key to encode the rest
    | otherwise = assert (srcLength < blockSize && srcLength > keyLength) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (blockSize + blockSize) -- one block for alignment, other to store new key
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyLength
            let (Keystream key nextKey) = keyStream
            poke (castPtr dstPtr') key
            void $ bytesXor2 dstPtr' srcPtr' (srcLength - keyLength)
            return  $ CryptProcess $ continueCrypt (fromForeignPtr (castForeignPtr dstFp) (keyUsed + srcLength) (blockSize - srcLength + keyLength)) nextKey
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    where
        (keyFp, keyOffset, keyLength) = toForeignPtr storedKey
        (srcFp, srcOffset, srcLength) = toForeignPtr src
        keyUsed = blockSize - keyLength
        (blockCount, remains) = assert (blockSize == 64) $ ((srcLength - keyLength) `unsafeShiftR` 6, (srcLength - keyLength) .&. 0x3F) -- (srcLength - keyLength) `quotRem` blockSize

{-# INLINE cryptChunk #-}
cryptChunk :: ForeignPtr Word8 -> Int -> Int -> (Ptr Block -> Ptr Word8 -> IO (ForeignPtr Block -> CryptProcess)) -> (ByteString, CryptProcess)
cryptChunk srcFp srcLen bufferSize f = unsafeDupablePerformIO $ do
    dstFp <- mallocForeignPtrBytes bufferSize
    cont <- withForeignPtr dstFp $ \dstBasePtr ->
            withForeignPtr srcFp $ \srcBasePtr ->
            f dstBasePtr srcBasePtr
    let process = cont dstFp
    return (fromForeignPtr (castForeignPtr dstFp) 0 srcLen, process)

{-# INLINE cryptRemains #-}
cryptRemains :: Ptr Block -> Int -> Ptr Word8 -> Keystream -> Int -> IO (ForeignPtr Block -> CryptProcess)
cryptRemains dstBasePtr dstOffset srcPtr (Keystream key nextKey) remains = do
    let dstPtr = dstBasePtr `plusPtr` dstOffset
    poke dstPtr key
    void $ bytesXor2 dstPtr srcPtr remains
    return $ \dstFp -> CryptProcess $ continueCrypt (fromForeignPtr (castForeignPtr dstFp) (dstOffset + remains) (blockSize - remains)) nextKey

{-# INLINE blockSize #-}
blockSize :: Int
blockSize = sizeOf (undefined :: Block)

-- | Encrypt whole number of blocks.
-- Number of bytes encrypted will be truncated to block boundary.
{-# INLINE blockXor #-}
blockXor :: Ptr Block -> Ptr Word8 -> Keystream -> Int -> IO (Keystream, Int)
blockXor dstPtr srcPtr keyStream size
    | srcPtr `alignPtr` alignment (undefined :: Block) == srcPtr = do
        stream <- blockXor3 dstPtr (castPtr srcPtr) keyStream blockBytes
        return (stream, blockBytes)
    | otherwise = do
        copyBytes (castPtr dstPtr) srcPtr blockBytes
        stream <- blockXor2 dstPtr keyStream blockBytes
        return (stream, blockBytes)
    where
        blockBytes = assert (blockSize == 64) $ size .&. (complement 0x3F)

-- | 2-address block crypt
{-# INLINE blockXor2 #-}
blockXor2 :: Ptr Block -> Keystream -> Int -> IO Keystream
blockXor2 dstPtr keyStream@(Keystream key nextKey) size
    | size == 0 = return keyStream
    | otherwise = assert (size `rem` blockSize == 0) $ do
        block <- peek dstPtr
        poke dstPtr $ block `xorBlock` key
        blockXor2 (dstPtr `plusPtr` blockSize) nextKey (size - blockSize)

-- | 3-address block crypt
{-# INLINE blockXor3 #-}
blockXor3 :: Ptr Block -> Ptr Block -> Keystream -> Int -> IO Keystream
blockXor3 dstPtr srcPtr keyStream@(Keystream key nextKey) size
    | size == 0 = return keyStream
    | otherwise = assert (size `rem` blockSize == 0) $ do
        block <- peek srcPtr
        poke dstPtr $ block `xorBlock` key
        blockXor3 (dstPtr `plusPtr` blockSize) (srcPtr `plusPtr` blockSize) nextKey (size - blockSize)

{-# INLINE copySourceIfUnaligned #-}
copySourceIfUnaligned :: Ptr Block -> Ptr Word8 -> Int -> IO (Ptr Block)
copySourceIfUnaligned dstPtr srcPtr size
  --  | srcPtr `alignPtr` alignment (undefined :: Block) == srcPtr = return $ castPtr srcPtr
    | otherwise = do
        copyBytes (castPtr dstPtr) srcPtr size
        return dstPtr

{-# INLINE cryptBlocks #-}
cryptBlocks :: Keystream -> Int -> Ptr Block -> Ptr Block -> IO (Ptr Block, Keystream)
cryptBlocks keyStream@(Keystream key nextKey) blocks dstPtr srcPtr
    | blocks == 0 = return $ (dstPtr, keyStream)
    | otherwise = assert (blocks > 0) $ do
        block <- peek srcPtr
        poke dstPtr $ block `xorBlock` key
        cryptBlocks nextKey (blocks - 1) (dstPtr `plusPtr` blockSize) (srcPtr `plusPtr` blockSize)

-- | 2-address string xor
{-# INLINE bytesXor2 #-}
bytesXor2 :: Ptr Word8 -> Ptr Word8 -> Int -> IO (Ptr Word8, Ptr Word8)
bytesXor2 dstPtr srcPtr count
    | count == 0 = return (dstPtr, srcPtr)
    | otherwise = assert (count > 0) $ do
        x <- peek dstPtr
        y <- peek srcPtr
        poke dstPtr (x `xor` y)
        bytesXor2 (dstPtr `plusPtr` 1) (srcPtr `plusPtr` 1) (count - 1)

-- | 3-address string xor
{-# INLINE bytesXor3 #-}
bytesXor3 :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO (Ptr Word8, Ptr Word8, Ptr Word8)
bytesXor3 dstPtr srcPtr keyPtr count
    | count == 0 = return (dstPtr, srcPtr, keyPtr)
    | otherwise = assert (count > 0) $ do
        x <- peek srcPtr
        y <- peek keyPtr
        poke dstPtr (x `xor` y)
        bytesXor3 (dstPtr `plusPtr` 1) (srcPtr `plusPtr` 1) (keyPtr `plusPtr` 1) (count - 1)

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