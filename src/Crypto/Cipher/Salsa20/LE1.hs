module Crypto.Cipher.Salsa20.LE1 where

import           Control.Exception
import           Data.Bits
import           Data.Word
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable

{-# INLINE doubleRound #-}
doubleRound :: Ptr Word32 -> IO ()
doubleRound state = do
    shuffle  4  0 12  7
    shuffle  9  5  1  7
    shuffle 14 10  6  7
    shuffle  3 15 11  7
    shuffle  8  4  0  9
    shuffle 13  9  5  9
    shuffle  2 14 10  9
    shuffle  7  3 15  9
    shuffle 12  8  4 13
    shuffle  1 13  9 13
    shuffle  6  2 14 13
    shuffle 11  7  3 13
    shuffle  0 12  8 18
    shuffle  5  1 13 18
    shuffle 10  6  2 18
    shuffle 15 11  7 18

    shuffle  1  0  3  7
    shuffle  6  5  4  7
    shuffle 11 10  9  7
    shuffle 12 15 14  7
    shuffle  2  1  0  9
    shuffle  7  6  5  9
    shuffle  8 11 10  9
    shuffle 13 12 15  9
    shuffle  3  2  1 13
    shuffle  4  7  6 13
    shuffle  9  8 11 13
    shuffle 14 13 12 13
    shuffle  0  3  2 18
    shuffle  5  4  7 18
    shuffle 10  9  8 18
    shuffle 15 14 13 18
    where
        {-# INLINE shuffle #-}
        shuffle :: Int -> Int -> Int -> Int -> IO ()
        shuffle ix ia ib shift = do
            x <- peekElemOff state ix
            a <- peekElemOff state ia
            b <- peekElemOff state ib
            pokeElemOff state ix $ x `xor` ((a + b) `rotateL` shift)

{-# INLINE salsa #-}
salsa :: Int -> Ptr Word32 -> IO ()
salsa rounds ptr = assert ((even rounds) && (rounds > 0)) $ allocaBytes 64 $ \buffer -> do
    forEach buffer ptr (flip const)
    go buffer (rounds `unsafeShiftR` 1)
    forEach ptr buffer (+)
    where
        {-# INLINE go #-}
        go :: Ptr Word32 -> Int -> IO ()
        go buffer i
            | i == 0 = return ()
            | otherwise = do
                doubleRound buffer
                go buffer (i - 1)

        {-# INLINE forEach #-}
        forEach :: Ptr Word32 -> Ptr Word32 -> (Word32 -> Word32 -> Word32) -> IO ()
        forEach dst src f = do  { on 0; on 1; on 2; on 3; on 4; on 5; on 6; on 7; on 8; on 9; on 10; on 11; on 12; on 13; on 14; on 15; on 16; }
                                where
                                    {-# INLINE on #-}
                                    on :: Int -> IO ()
                                    on i = do
                                        a <- peekElemOff dst i
                                        b <- peekElemOff src i
                                        pokeElemOff dst i $ f a b