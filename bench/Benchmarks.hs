module Benchmarks where

import           Criterion.Main
import           Crypto.Cipher.Salsa20
import           Data.ByteString

testState :: Block
testState = Block (Quarter 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                  (Quarter 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                  (Quarter 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                  (Quarter 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a)

testStateSerialized :: ByteString
testStateSerialized = writeBinary testState

main :: IO ()
main = defaultMain
    [ bgroup "salsa core"
        [ bench "quarterround" $ whnf quarterround $ Quarter 0x00000000 0x00000000 0x00000000 0x00000000
        , bench "rowround" $ whnf rowround testState
        , bench "columnround" $ whnf columnround testState
        , bench "doubleround" $ whnf doubleround testState
        , bench "salsa20" $ whnf (salsa 20) testState
        , bench "readBinary" $ whnf (readBinary :: ByteString -> Maybe (Block, ByteString)) testStateSerialized
        , bench "writeBinary" $ whnf writeBinary testState
        ]
    ]