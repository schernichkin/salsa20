module Benchmarks where

import           Criterion.Main
import           Crypto.Cipher.Salsa20
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as BS
import           Data.Maybe

coreBench :: Benchmark
coreBench = bgroup "core"
    [ bench "salsa 8" $ whnf (salsa 8) $ block
    , bench "salsa 12" $ whnf (salsa 12) $ block
    , bench "salsa 20" $ whnf (salsa 20) $ block
    ]
    where
        block :: Block
        block = fst $ fromJust $ readBlock $ BS.replicate 64 0

cryptBench :: Int -> Benchmark
cryptBench rounds = bgroup ("crypt with salsa " ++ show rounds)
    [ bench "10 bytes chunk" $ whnf cryptChunk $ BS.replicate 10 0
    , bench "100 bytes chunk" $ whnf cryptChunk $ BS.replicate 100 0
    , bench "1K bytes chunk" $ whnf cryptChunk $ BS.replicate 1024 0
    , bench "1M bytes chunk" $ whnf cryptChunk $ BS.replicate 1048576 0
    , bench "100M bytes chunk" $ whnf cryptChunk $ BS.replicate 104857600 0
    , bench "100M in 64 bytes chunks + concat" $ whnf cryptAll $ replicate 1638400 $ BS.replicate 64 0
    , bench "100M in 100 bytes chunks + concat" $ whnf cryptAll $ replicate 1048576 $ BS.replicate 100 0
    , bench "100M in 32k bytes chunks + concat" $ whnf cryptAll $ replicate 3200 $ BS.replicate 32768 0
    ]
    where
        cryptChunk :: ByteString -> ByteString
        cryptChunk byteString = fst $ runCryptProcess cryptProcess byteString

        cryptAll :: [ByteString] -> ByteString
        cryptAll = BS.concat . go cryptProcess
            where
                go cp (x:xs) = let (bs', cp') = runCryptProcess cp x in bs' : go cp' xs
                go _ [] = []

        cryptProcess :: CryptProcess
        cryptProcess = (crypt (salsa rounds) key nounce 0)
            where
                key = fst $ fromJust $ readKey256 $ BS.replicate 32 0
                nounce = fst $ fromJust $ readNounce $ BS.replicate 8 0

main :: IO ()
main = defaultMain
    [ coreBench
    , cryptBench 8
    , cryptBench 12
    , cryptBench 20
    ]