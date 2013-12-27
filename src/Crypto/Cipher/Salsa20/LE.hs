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

-- TODO: finally replace with bytestring
data StoredKey = StoredKey {-# UNPACK #-} !(ForeignPtr Word8) -- ^ Pointer to the base block (shared with bytestring)
                           {-# UNPACK #-} !Int                -- ^ Offset in the base block
                           {-# UNPACK #-} !Int                -- ^ Number of bytes already consumed (i.e size of the stored key = block size - number of bytes already consumed) TODO: replace with key size
                           {-# UNPACK #-} !Int                -- ^ Key length

-- TODO: использовать битовые операции вместо `quotRem` (добавить assert), уменьшить количество кейсов.
{-# INLINE startCrypt #-}
startCrypt :: Keystream -> ByteString -> (ByteString, CryptProcess)
startCrypt keyStream src
    -- encode exactly one block (this can be removed because covered by "encode whole number of blocks" but it may be little bit faster, because does not requre `quotRem` )
    | srcLength == blockSize = unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes srcLength
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr -> do
            alignedSrcPtr <- copySourceIfUnaligned dstBasePtr (srcBasePtr `plusPtr` srcOffset) srcLength
            block <- peek alignedSrcPtr
            let (Keystream key nextKey) = keyStream
            poke dstBasePtr (block `xorBlock` key)
            return $ CryptProcess $ startCrypt nextKey
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    -- encode whole number of blocks (more than one, one is handled by special case)
    | srcLength > blockSize && bytesRemains == 0 = assert (blockCount > 1) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes srcLength
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr -> do
            alignedSrcPtr <- copySourceIfUnaligned dstBasePtr (srcBasePtr `plusPtr` srcOffset) srcLength
            nextKey' <- snd <$> cryptBlocks keyStream blockCount dstBasePtr alignedSrcPtr
            return $ CryptProcess $ startCrypt nextKey'
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    -- encode one or more block + part of the key and store key remains for the next step
    | srcLength > blockSize = assert (bytesRemains > 0) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes (srcLength + blockSize - bytesRemains)
        process <- withForeignPtr dstFp $ \dstPtr ->
                   withForeignPtr srcFp $ \srcBasePtr -> do
            alignedSrcPtr <- copySourceIfUnaligned dstPtr (srcBasePtr `plusPtr` srcOffset) srcLength
            (dstPtr', keyStream'@(Keystream key' nextKey')) <- cryptBlocks keyStream blockCount dstPtr alignedSrcPtr
            poke dstPtr' key'
            void $ bytesXor2 (castPtr dstPtr') (srcBasePtr `plusPtr` (srcOffset + srcLength - bytesRemains)) bytesRemains
            return  $ CryptProcess $ continueCrypt (StoredKey (castForeignPtr dstFp) srcLength bytesRemains (blockSize - bytesRemains)) nextKey'
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    -- skip empty block
    | srcLength == 0 = (src, CryptProcess $ startCrypt keyStream)
    -- encode less then one block and store key remains
    | otherwise = assert (srcLength < blockSize) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes blockSize
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr -> do
            let (Keystream key nextKey) = keyStream
            poke dstBasePtr key
            void $ bytesXor2 (castPtr dstBasePtr) (srcBasePtr `plusPtr` srcOffset) srcLength
            return  $ CryptProcess $ continueCrypt (StoredKey (castForeignPtr dstFp) srcLength srcLength (blockSize - srcLength)) nextKey
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    where
        (srcFp, srcOffset, srcLength) = toForeignPtr src
        (blockCount, bytesRemains) = srcLength `quotRem` blockSize

{-# INLINE continueCrypt #-}
continueCrypt :: StoredKey -> Keystream -> ByteString -> (ByteString, CryptProcess)
continueCrypt a@(StoredKey keyFp keyOffset keyUsed) keyStream src
    -- use all key remains to encode chunk
    | srcLength == keyRemains = unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes srcLength
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            bytesXor3 (castPtr dstBasePtr) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) srcLength
            return $ CryptProcess $ startCrypt keyStream
        return (fromForeignPtr (castForeignPtr dstFp) 0 srcLength, process)
    -- use all key remains and exactly one block 
    | srcLength == keyRemains + blockSize = unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes (blockSize + blockSize)
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyRemains
            alignedSrcPtr' <- copySourceIfUnaligned (castPtr dstPtr') srcPtr' blockSize
            block <- peek alignedSrcPtr'
            let (Keystream key nextKey) = keyStream
            poke (castPtr dstPtr') (block `xorBlock` key)
            return $ CryptProcess $ startCrypt nextKey
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process) 
    -- use all key remains + some whole key blocks (more than one, one is handled by special case)
    | srcLength >= blockSize && bytesRemains == 0 = assert (blockCount > 1) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (srcLength + blockSize)
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyRemains
            alignedSrcPtr <- copySourceIfUnaligned (castPtr dstPtr') srcPtr' (srcLength - keyRemains)
            nextKey' <- snd <$> cryptBlocks keyStream blockCount (castPtr dstPtr') alignedSrcPtr
            return $ CryptProcess $ startCrypt nextKey'
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    -- use all key remains + some whole key blocks + part of the key and store key remains for the next step
    | srcLength >= blockSize = assert (bytesRemains > 0) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (srcLength + blockSize + blockSize) -- one block for alignment one for new key remains
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyRemains
            alignedSrcPtr' <- copySourceIfUnaligned (castPtr dstPtr') srcPtr' (srcLength - keyRemains - bytesRemains)
            (dstPtr'', keyStream''@(Keystream key'' nextKey'')) <- cryptBlocks keyStream blockCount (castPtr dstPtr') alignedSrcPtr'
            poke dstPtr'' key''
            void $ bytesXor2 (castPtr dstPtr'') (srcPtr' `plusPtr` (srcLength - bytesRemains - keyRemains)) bytesRemains
            return  $ CryptProcess $ continueCrypt (StoredKey (castForeignPtr dstFp) (keyUsed + srcLength) bytesRemains) nextKey''
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    -- skip empty block
    | srcLength == 0 = (src, CryptProcess $ continueCrypt a keyStream)
    -- use some of key remains to encode the block and store remains in the new block to allow GC reclaim old block
    | srcLength < keyRemains = assert (srcLength > 0) $ unsafeDupablePerformIO $ do
        dstFp <- mallocForeignPtrBytes (srcLength + (keyRemains - srcLength))
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', keyPtr') <- bytesXor3 dstBasePtr (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) srcLength
            copyBytes dstPtr' keyPtr' (keyRemains - srcLength)
            return $ CryptProcess $ continueCrypt (StoredKey (castForeignPtr dstFp) srcLength (keyUsed + srcLength)) keyStream
        return (fromForeignPtr dstFp 0 srcLength, process)
    -- use all key remains to encode the block and part of new key to encode the rest
    | otherwise = assert (srcLength < blockSize && srcLength > keyRemains) $ unsafeDupablePerformIO $ do
        dstFp <- (\a -> a `asTypeOf` (undefined :: ForeignPtr Block)) <$> mallocForeignPtrBytes (blockSize + blockSize) -- one block for alignment, other to store new key
        process <- withForeignPtr dstFp $ \dstBasePtr ->
                   withForeignPtr srcFp $ \srcBasePtr ->
                   withForeignPtr keyFp $ \keyBasePtr -> do
            (dstPtr', srcPtr', _) <- bytesXor3 (dstBasePtr `plusPtr` keyUsed) (srcBasePtr `plusPtr` srcOffset) (keyBasePtr `plusPtr` keyOffset) keyRemains
            let (Keystream key nextKey) = keyStream
            poke (castPtr dstPtr') key
            void $ bytesXor2 dstPtr' srcPtr' (srcLength - keyRemains)
            return  $ CryptProcess $ continueCrypt (StoredKey (castForeignPtr dstFp) (keyUsed + srcLength) (srcLength - keyRemains)) nextKey
        return (fromForeignPtr (castForeignPtr dstFp) keyUsed srcLength, process)
    where
        (srcFp, srcOffset, srcLength) = toForeignPtr src
        keyRemains = (blockSize - keyUsed)
        (blockCount, bytesRemains) = (srcLength - keyRemains) `quotRem` blockSize

{-# INLINE blockSize #-}
blockSize :: Int
blockSize = sizeOf (undefined :: Block)

{-# INLINE copySourceIfUnaligned #-}
copySourceIfUnaligned :: Ptr Block -> Ptr Word8 -> Int -> IO (Ptr Block)
copySourceIfUnaligned dstPtr srcPtr size
    | srcPtr `alignPtr` alignment (undefined :: Block) == srcPtr = return $ castPtr srcPtr
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