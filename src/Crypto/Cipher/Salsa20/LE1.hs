module Crypto.Cipher.Salsa20.LE1 where

import           Control.Exception
import           Data.Bits
import           Data.Word
import           Foreign.Marshal.Alloc
import           Foreign.Marshal.Utils
import           Foreign.Ptr
import           Foreign.Storable

newtype Shuffle a = Shuffle { runShuffle :: Ptr Word32 -> IO a }

instance Monad Shuffle where
    {-# INLINE (>>=) #-}
    f >>= g = Shuffle $ \ptr -> do
                  a <- runShuffle f ptr
                  runShuffle (g a) ptr

    {-# INLINE (>>) #-}
    f >> g = Shuffle $ \ptr -> do
                  runShuffle f ptr
                  runShuffle g ptr

    {-# INLINE return #-}
    return a = Shuffle $ const $ return a

{-# INLINE shuffle #-}
shuffle :: Int -> Int -> Int -> Int -> Shuffle ()
shuffle ix ia ib shift = Shuffle $ \ptr -> do
    x <- peekElemOff ptr ix
    a <- peekElemOff ptr ia
    b <- peekElemOff ptr ib
    pokeElemOff ptr ix $ x `xor` ((a + b) `rotateL` shift)

{-# INLINE doubleRound #-}
doubleRound :: Shuffle ()
doubleRound = do
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

{-# INLINE salsa #-}
salsa :: Int -> Ptr Word32 -> IO ()
salsa rounds ptr = assert ((even rounds) && (rounds > 0)) $ allocaBytes 64 $ \buffer -> do
    copyBytes buffer ptr 64
    go buffer (rounds `unsafeShiftR` 1)
    compose ptr buffer 64
    where
        go :: Ptr Word32 -> Int -> IO ()
        go buffer i
            | i == 0 = return ()
            | otherwise = do
                runShuffle doubleRound buffer
                go buffer (i - 1)

        compose :: Ptr Word32 -> Ptr Word32 -> Int -> IO ()
        compose dst src i
            | i == 0    = return ()
            | otherwise = do
                x <- peekElemOff dst i
                y <- peekElemOff src i
                pokeElemOff dst i (x + y)
