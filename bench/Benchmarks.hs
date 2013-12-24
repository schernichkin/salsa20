module Benchmarks where

import           Criterion.Main
import           Crypto.Cipher.Salsa20 as LE
import           Data.ByteString
import           Crypto.Cipher.Salsa20.LE1 as LE1
import           Foreign.Marshal.Alloc
import System.IO.Unsafe
import           Foreign.Storable

testState :: Block
testState = Block (Quarter 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                  (Quarter 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                  (Quarter 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                  (Quarter 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a)

testStateSerialized :: ByteString
testStateSerialized = writeBinary testState

testKey128 = Key128 (Quarter 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a)
testNounce = Nounce 0 0 
testSeqNum = 0
testData64 = pack [0..255]

main :: IO ()
main = defaultMain
    [ bgroup "salsa core"
        [ {- bench "quarterround" $ whnf quarterround $ Quarter 0x00000000 0x00000000 0x00000000 0x00000000
        , bench "rowround" $ whnf rowround testState
        , bench "columnround" $ whnf columnround testState
        , bench "doubleround" $ whnf doubleround testState
        , bench "salsa20" $ whnf (salsa 20) testState
        , bench "readBinary" $ whnf (readBinary :: ByteString -> (Block, ByteString)) testStateSerialized
        , bench "writeBinary" $ whnf writeBinary testState 
        , -} bench "crypt (256 bytes)" $ whnf (\d -> let (CryptProcess c) = crypt (LE.salsa 20)
                                                                              testKey128
                                                                              testNounce
                                                                              testSeqNum
                                                 in fst $ c d) (testData64)
        , bench "salsa 1000000 (LE)" $ whnf (LE.salsa 1000000) testState
        , bench "salsa 1000000 (LE1)"  $ whnf (\_ -> unsafeDupablePerformIO $ allocaBytes 64 $ \buffer -> LE1.salsa 1000000 buffer >> peekElemOff buffer 0) ()
        ]
    ]